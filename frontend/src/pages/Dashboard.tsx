import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { projectApi } from '../api/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { FileCode, Activity, Database, Search, List as ListIcon, Code, HelpCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '../lib/utils';

export function Dashboard() {
  const [activeTab, setActiveTab] = useState<'binaries' | 'functions' | 'strings' | 'about'>('binaries');

  // Overview
  const { data: overview, isLoading: isOverviewLoading } = useQuery({
    queryKey: ['projectOverview'],
    queryFn: projectApi.getOverview,
  });

  // Binaries List
  const { data: binaries } = useQuery({
    queryKey: ['projectBinaries'],
    queryFn: () => projectApi.listBinaries(0, 50),
    enabled: activeTab === 'binaries',
  });

  // Function Search
  const [funcQuery, setFuncQuery] = useState('');
  const [funcMatch, setFuncMatch] = useState('contains');
  const [triggerFuncSearch, setTriggerFuncSearch] = useState(0);
  
  const { data: funcResults, isLoading: isFuncLoading } = useQuery({
    queryKey: ['searchFunctions', funcQuery, funcMatch, triggerFuncSearch],
    queryFn: () => projectApi.searchFunctions(funcQuery, funcMatch),
    enabled: activeTab === 'functions' && triggerFuncSearch > 0 && !!funcQuery,
  });

  const handleFuncSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (funcQuery) setTriggerFuncSearch(p => p + 1);
  };

  // String Search
  const [strQuery, setStrQuery] = useState('');
  const [strMatch, setStrMatch] = useState('contains');
  const [triggerStrSearch, setTriggerStrSearch] = useState(0);

  const { data: strResults, isLoading: isStrLoading } = useQuery({
    queryKey: ['searchStrings', strQuery, strMatch, triggerStrSearch],
    queryFn: () => projectApi.searchStrings(strQuery, strMatch),
    enabled: activeTab === 'strings' && triggerStrSearch > 0 && !!strQuery,
  });

  const handleStrSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (strQuery) setTriggerStrSearch(p => p + 1);
  };

  // MCP Tools
  const { data: mcpTools, isLoading: isMcpToolsLoading } = useQuery({
    queryKey: ['mcpTools'],
    queryFn: projectApi.getMcpTools,
    enabled: activeTab === 'about',
  });

  if (isOverviewLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="container py-6 space-y-6">
      {/* Overview Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Binaries</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.binaries_count || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Analysis Status</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.analysis_status || "Unknown"}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Project ID</CardTitle>
            <FileCode className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground truncate" title={overview?.project}>
              {overview?.project || "N/A"}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Area */}
      <div>
        <div className="flex space-x-1 border-b mb-4">
          <Button 
            variant={activeTab === 'binaries' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('binaries')}
            className={cn("rounded-b-none", activeTab === 'binaries' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <ListIcon className="mr-2 h-4 w-4"/> Binaries
          </Button>
          <Button 
            variant={activeTab === 'functions' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('functions')}
            className={cn("rounded-b-none", activeTab === 'functions' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <Code className="mr-2 h-4 w-4"/> Search Functions
          </Button>
          <Button 
            variant={activeTab === 'strings' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('strings')}
            className={cn("rounded-b-none", activeTab === 'strings' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <Search className="mr-2 h-4 w-4"/> Search Strings
          </Button>
          <Button 
            variant={activeTab === 'about' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('about')}
            className={cn("rounded-b-none", activeTab === 'about' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <HelpCircle className="mr-2 h-4 w-4"/> About & Help
          </Button>
        </div>

        {/* Binaries Tab */}
        {activeTab === 'binaries' && (
          <div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {binaries?.map((binary) => (
                <Link key={binary.binary_name} to={`/binary/${encodeURIComponent(binary.binary_name)}/overview`}>
                  <Card className="hover:bg-muted/50 transition-colors cursor-pointer h-full">
                    <CardHeader>
                      <CardTitle className="truncate" title={binary.binary_name}>{binary.binary_name}</CardTitle>
                      <CardDescription>{binary.arch || "Unknown Arch"}</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="text-sm text-muted-foreground space-y-1">
                        <div className="flex justify-between">
                          <span>Size:</span>
                          <span>{binary.size ? (binary.size / 1024).toFixed(2) + ' KB' : 'N/A'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Functions:</span>
                          <span>{binary.function_count !== undefined ? binary.function_count : 'N/A'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Imported:</span>
                          <span>{binary.created_at ? new Date(binary.created_at).toLocaleDateString() : 'N/A'}</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </Link>
              ))}
              {binaries && binaries.length === 0 && (
                <div className="text-muted-foreground col-span-full text-center py-10">
                   No binaries found in this project.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Function Search Tab */}
        {activeTab === 'functions' && (
          <div className="space-y-4">
             <form onSubmit={handleFuncSearch} className="flex gap-2">
               <Input 
                 placeholder="Search function name..." 
                 value={funcQuery}
                 onChange={(e) => setFuncQuery(e.target.value)}
                 className="max-w-md"
               />
               <select 
                 className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                 value={funcMatch}
                 onChange={(e) => setFuncMatch(e.target.value)}
               >
                 <option value="contains">Contains</option>
                 <option value="exact">Exact</option>
                 <option value="regex">Regex</option>
               </select>
               <Button type="submit" disabled={isFuncLoading}>
                 {isFuncLoading ? 'Searching...' : 'Search'}
               </Button>
             </form>

             {isFuncLoading && <div className="py-4 text-muted-foreground">Searching...</div>}

             <div className="space-y-2">
               {funcResults?.map((hit, idx) => (
                 <Link key={idx} to={`/binary/${encodeURIComponent(hit.binary)}/functions/${encodeURIComponent(hit.function.address)}`}>
                   <div className="p-3 border rounded-md hover:bg-muted/50 transition-colors">
                     <div className="flex justify-between items-center">
                       <div className="font-mono text-sm font-bold text-primary">{hit.function.name}</div>
                       <div className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded">{hit.binary}</div>
                     </div>
                     <div className="text-xs text-muted-foreground font-mono mt-1">
                       {hit.function.address} {hit.function.is_library ? '(Library)' : ''}
                     </div>
                   </div>
                 </Link>
               ))}
               {funcResults && funcResults.length === 0 && (
                 <div className="text-muted-foreground py-4">No functions found.</div>
               )}
             </div>
          </div>
        )}

        {/* String Search Tab */}
        {activeTab === 'strings' && (
          <div className="space-y-4">
             <form onSubmit={handleStrSearch} className="flex gap-2">
               <Input 
                 placeholder="Search strings..." 
                 value={strQuery}
                 onChange={(e) => setStrQuery(e.target.value)}
                 className="max-w-md"
               />
               <select 
                 className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                 value={strMatch}
                 onChange={(e) => setStrMatch(e.target.value)}
               >
                 <option value="contains">Contains</option>
                 <option value="exact">Exact</option>
                 <option value="regex">Regex</option>
               </select>
               <Button type="submit" disabled={isStrLoading}>
                 {isStrLoading ? 'Searching...' : 'Search'}
               </Button>
             </form>

             {isStrLoading && <div className="py-4 text-muted-foreground">Searching...</div>}

             <div className="space-y-2">
               {strResults?.map((hit, idx) => (
                 <Link key={idx} to={`/binary/${encodeURIComponent(hit.binary)}/strings?address=${encodeURIComponent(hit.address)}`}>
                   <div className="p-3 border rounded-md hover:bg-muted/50 transition-colors">
                     <div className="flex justify-between items-start gap-4">
                       <div className="font-mono text-sm break-all">{hit.string}</div>
                       <div className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded shrink-0">{hit.binary}</div>
                     </div>
                     <div className="text-xs text-muted-foreground font-mono mt-1">
                       {hit.address}
                     </div>
                   </div>
                 </Link>
               ))}
               {strResults && strResults.length === 0 && (
                 <div className="text-muted-foreground py-4">No strings found.</div>
               )}
             </div>
          </div>
        )}

        {/* About & Help Tab */}
        {activeTab === 'about' && (
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>About IDA Project MCP Service</CardTitle>
                <CardDescription>
                  This service exposes static analysis data from your IDA Pro projects through the Model Context Protocol (MCP) compatible interface.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <p>
                  The service allows LLM agents (like Claude) to inspect binary analysis results, including functions, strings, cross-references, and disassembly.
                </p>
                
                <div className="bg-muted p-4 rounded-md">
                  <h3 className="font-semibold mb-2 flex items-center gap-2">
                    <Activity className="h-4 w-4" />
                    Getting Started
                  </h3>
                  <div className="space-y-4 text-sm">
                    <div>
                      <div className="font-medium mb-1">1. Export Analysis Data</div>
                      <p className="text-muted-foreground">
                        Use the <code>ida_exporter.py</code> script within IDA Pro to export your binary analysis database.
                      </p>
                    </div>
                    <div>
                      <div className="font-medium mb-1">2. Configure Server</div>
                      <p className="text-muted-foreground">
                        Set the <code>IDA_MCP_PROJECT</code> environment variable to your exported project directory.
                      </p>
                    </div>
                    <div>
                      <div className="font-medium mb-1">3. Connect MCP Client</div>
                      <p className="text-muted-foreground mb-2">
                        Configure your MCP client (e.g., Claude Desktop) to connect to this server.
                        Below is an example configuration for <code>claude_desktop_config.json</code>:
                      </p>
                      <pre className="bg-background p-2 rounded border text-xs overflow-auto font-mono">
{`{
  "mcpServers": {
    "ida-mcp": {
      "command": "python",
      "args": [
        "-m", 
        "ida_project_mcp.mcp_stdio_server", 
        "--project", 
        "C:/path/to/your/project"
      ]
    }
  }
}`}
                      </pre>
                      <p className="text-xs text-muted-foreground mt-2">
                        * Note: Ensure the <code>aida-mcp</code> package is installed or in your PYTHONPATH.
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <div>
              <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                <Code className="h-5 w-5" />
                Available Tools
              </h2>
              {isMcpToolsLoading ? (
                <div className="py-8 text-center text-muted-foreground">Loading available tools...</div>
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
                  {mcpTools?.map((tool) => (
                    <Card key={tool.name} className="flex flex-col">
                      <CardHeader className="pb-2">
                        <CardTitle className="font-mono text-base text-primary">{tool.name}</CardTitle>
                        <CardDescription className="text-sm mt-1 whitespace-pre-wrap">{tool.description}</CardDescription>
                      </CardHeader>
                      <CardContent className="flex-1">
                        <div className="text-xs font-semibold mb-2 text-muted-foreground uppercase tracking-wider">Parameters</div>
                        <div className="bg-muted p-3 rounded-md text-xs font-mono overflow-x-auto">
                          <ul className="list-disc list-inside space-y-1">
                            {Object.entries(tool.inputSchema.properties).map(([param, details]) => (
                              <li key={param}>
                                <span className="font-bold text-foreground">{param}</span>
                                <span className="text-muted-foreground ml-1">({details.type})</span>
                                {tool.inputSchema.required?.includes(param) && (
                                  <span className="ml-2 text-red-500 text-[10px] uppercase font-bold">Required</span>
                                )}
                              </li>
                            ))}
                            {Object.keys(tool.inputSchema.properties).length === 0 && (
                              <li className="text-muted-foreground italic">No parameters required</li>
                            )}
                          </ul>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
