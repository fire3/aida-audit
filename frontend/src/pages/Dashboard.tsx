import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { projectApi } from '../api/client';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { FileCode, Activity, Database, Search, List as ListIcon, Code, HelpCircle, Info, Hammer } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn, formatAddress } from '../lib/utils';
import { McpToolsTab } from '../components/McpToolsTab';
import { HelpTab } from '../components/HelpTab';
import { AboutTab } from '../components/AboutTab';
import { useTranslation } from 'react-i18next';

export function Dashboard() {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState<'binaries' | 'functions' | 'strings' | 'mcp_tools' | 'help' | 'about'>('binaries');

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

  if (isOverviewLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="container py-6 space-y-6">
      {/* Overview Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('dashboard.stats.total_binaries')}</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.binaries_count || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('dashboard.stats.analysis_status')}</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.analysis_status || "Unknown"}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('dashboard.stats.project_id')}</CardTitle>
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
        <div className="flex space-x-1 border-b mb-4 overflow-x-auto">
          <Button 
            variant={activeTab === 'binaries' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('binaries')}
            className={cn("rounded-b-none", activeTab === 'binaries' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <ListIcon className="mr-2 h-4 w-4"/> {t('dashboard.tabs.binaries')}
          </Button>
          <Button 
            variant={activeTab === 'functions' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('functions')}
            className={cn("rounded-b-none", activeTab === 'functions' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <Code className="mr-2 h-4 w-4"/> {t('dashboard.tabs.search_functions')}
          </Button>
          <Button 
            variant={activeTab === 'strings' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('strings')}
            className={cn("rounded-b-none", activeTab === 'strings' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <Search className="mr-2 h-4 w-4"/> {t('dashboard.tabs.search_strings')}
          </Button>
          <Button 
            variant={activeTab === 'mcp_tools' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('mcp_tools')}
            className={cn("rounded-b-none", activeTab === 'mcp_tools' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <Hammer className="mr-2 h-4 w-4"/> {t('dashboard.tabs.mcp_tools')}
          </Button>
          <Button 
            variant={activeTab === 'help' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('help')}
            className={cn("rounded-b-none", activeTab === 'help' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <HelpCircle className="mr-2 h-4 w-4"/> {t('dashboard.tabs.help')}
          </Button>
          <Button 
            variant={activeTab === 'about' ? 'default' : 'ghost'} 
            onClick={() => setActiveTab('about')}
            className={cn("rounded-b-none", activeTab === 'about' ? "bg-muted text-primary hover:bg-muted" : "hover:bg-muted/50")}
          >
            <Info className="mr-2 h-4 w-4"/> {t('dashboard.tabs.about')}
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
                      <CardDescription>{binary.arch || t('dashboard.binary_card.unknown_arch')}</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="text-sm text-muted-foreground space-y-1">
                        <div className="flex justify-between">
                          <span>{t('dashboard.binary_card.size')}</span>
                          <span>{binary.size ? (binary.size / 1024).toFixed(2) + ' KB' : 'N/A'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>{t('dashboard.binary_card.functions')}</span>
                          <span>{binary.function_count !== undefined ? binary.function_count : 'N/A'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>{t('dashboard.binary_card.imported')}</span>
                          <span>{binary.created_at ? new Date(binary.created_at).toLocaleDateString() : 'N/A'}</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </Link>
              ))}
              {binaries && binaries.length === 0 && (
                <div className="text-muted-foreground col-span-full text-center py-10">
                   {t('dashboard.binary_card.no_binaries')}
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
                 placeholder={t('dashboard.search.function_placeholder')}
                 value={funcQuery}
                 onChange={(e) => setFuncQuery(e.target.value)}
                 className="max-w-md"
               />
               <select 
                 className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                 value={funcMatch}
                 onChange={(e) => setFuncMatch(e.target.value)}
               >
                 <option value="contains">{t('dashboard.search.match_contains')}</option>
                 <option value="exact">{t('dashboard.search.match_exact')}</option>
                 <option value="regex">{t('dashboard.search.match_regex')}</option>
               </select>
               <Button type="submit" disabled={isFuncLoading}>
                 {isFuncLoading ? t('dashboard.search.searching') : t('dashboard.search.search_btn')}
               </Button>
             </form>

             {isFuncLoading && <div className="py-4 text-muted-foreground">{t('dashboard.search.searching')}</div>}

             <div className="space-y-2">
               {funcResults?.map((hit, idx) => (
                 <Link key={idx} to={`/binary/${encodeURIComponent(hit.binary)}/functions/${encodeURIComponent(hit.function.address)}`}>
                   <div className="p-3 border rounded-md hover:bg-muted/50 transition-colors">
                     <div className="flex justify-between items-center">
                       <div className="font-mono text-sm font-bold text-primary">{hit.function.name}</div>
                       <div className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded">{hit.binary}</div>
                     </div>
                     <div className="text-xs text-muted-foreground font-mono mt-1">
                       {formatAddress(hit.function.address)} {hit.function.is_library ? t('dashboard.search.library') : ''}
                     </div>
                   </div>
                 </Link>
               ))}
               {funcResults && funcResults.length === 0 && (
                 <div className="text-muted-foreground py-4">{t('dashboard.search.no_functions')}</div>
               )}
             </div>
          </div>
        )}

        {/* String Search Tab */}
        {activeTab === 'strings' && (
          <div className="space-y-4">
             <form onSubmit={handleStrSearch} className="flex gap-2">
               <Input 
                 placeholder={t('dashboard.search.string_placeholder')}
                 value={strQuery}
                 onChange={(e) => setStrQuery(e.target.value)}
                 className="max-w-md"
               />
               <select 
                 className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                 value={strMatch}
                 onChange={(e) => setStrMatch(e.target.value)}
               >
                 <option value="contains">{t('dashboard.search.match_contains')}</option>
                 <option value="exact">{t('dashboard.search.match_exact')}</option>
                 <option value="regex">{t('dashboard.search.match_regex')}</option>
               </select>
               <Button type="submit" disabled={isStrLoading}>
                 {isStrLoading ? t('dashboard.search.searching') : t('dashboard.search.search_btn')}
               </Button>
             </form>

             {isStrLoading && <div className="py-4 text-muted-foreground">{t('dashboard.search.searching')}</div>}

             <div className="space-y-2">
               {strResults?.map((hit, idx) => (
                 <Link key={idx} to={`/binary/${encodeURIComponent(hit.binary)}/strings?address=${encodeURIComponent(hit.address)}`}>
                   <div className="p-3 border rounded-md hover:bg-muted/50 transition-colors">
                     <div className="flex justify-between items-start gap-4">
                       <div className="font-mono text-sm break-all">{hit.string}</div>
                       <div className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded shrink-0">{hit.binary}</div>
                     </div>
                     <div className="text-xs text-muted-foreground font-mono mt-1">
                       {formatAddress(hit.address)}
                     </div>
                   </div>
                 </Link>
               ))}
               {strResults && strResults.length === 0 && (
                 <div className="text-muted-foreground py-4">{t('dashboard.search.no_strings')}</div>
               )}
             </div>
          </div>
        )}

        {/* MCP Tools Tab */}
        {activeTab === 'mcp_tools' && (
          <McpToolsTab />
        )}

        {/* Help Tab */}
        {activeTab === 'help' && (
          <HelpTab />
        )}

        {/* About Tab */}
        {activeTab === 'about' && (
          <AboutTab />
        )}
      </div>
    </div>
  );
}
