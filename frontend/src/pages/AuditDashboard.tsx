import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { auditApi, type AuditPlan } from '../api/client';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { useState, useMemo } from 'react';
import { 
  CheckCircle2, 
  Circle, 
  Clock, 
  AlertCircle, 
  ChevronRight, 
  ChevronDown, 
  Terminal, 
  MessageSquare, 
  Database, 
  ListTodo,
  Play,
  Square,
  StickyNote,
  AlertTriangle,
  Code
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

function Badge({ children, variant }: { children: React.ReactNode, variant: string }) {
    const colors = {
        default: "bg-green-100 text-green-800 border border-green-200",
        secondary: "bg-blue-100 text-blue-800 border border-blue-200",
        outline: "bg-gray-100 text-gray-800 border border-gray-200",
        destructive: "bg-red-100 text-red-800 border border-red-200",
        warning: "bg-yellow-100 text-yellow-800 border border-yellow-200",
        info: "bg-sky-100 text-sky-800 border border-sky-200",
        purple: "bg-purple-100 text-purple-800 border border-purple-200",
        orange: "bg-orange-100 text-orange-800 border border-orange-200"
    };
    const style = colors[variant as keyof typeof colors] || colors.outline;
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide ${style}`}>
            {children}
        </span>
    )
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'completed': return <CheckCircle2 className="w-4 h-4 text-green-500" />;
    case 'in_progress': return <Clock className="w-4 h-4 text-blue-500 animate-pulse" />;
    case 'failed': return <AlertCircle className="w-4 h-4 text-red-500" />;
    default: return <Circle className="w-4 h-4 text-gray-300" />;
  }
}

interface PlanNode extends AuditPlan {
  children: PlanNode[];
}

function buildPlanTree(plans: AuditPlan[]): PlanNode[] {
  const map = new Map<number, PlanNode>();
  const roots: PlanNode[] = [];

  // Initialize nodes
  plans.forEach(plan => {
    map.set(plan.id, { ...plan, children: [] });
  });

  // Build tree
  plans.forEach(plan => {
    const node = map.get(plan.id)!;
    if (plan.parent_id && map.has(plan.parent_id)) {
      map.get(plan.parent_id)!.children.push(node);
    } else {
      roots.push(node);
    }
  });

  return roots;
}

function PlanItem({ plan, depth = 0 }: { plan: PlanNode, depth?: number }) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = plan.children.length > 0;

  return (
    <div className="flex flex-col">
      <div 
        className={`flex items-start gap-2 py-2 px-2 hover:bg-slate-50 dark:hover:bg-slate-800/50 rounded-md transition-colors ${depth > 0 ? 'ml-6 border-l border-slate-100 dark:border-slate-800 pl-4' : ''}`}
      >
        <button 
          onClick={() => setExpanded(!expanded)}
          className={`mt-0.5 p-0.5 rounded-sm hover:bg-slate-200 dark:hover:bg-slate-700 ${!hasChildren ? 'invisible' : ''}`}
        >
          {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        </button>
        
        <div className="mt-0.5">
          <StatusIcon status={plan.status} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-medium text-sm truncate">{plan.title}</span>
            {plan.plan_type && (
                <Badge variant={plan.plan_type === 'audit_plan' ? 'purple' : 'orange'}>
                    {plan.plan_type === 'audit_plan' ? 'AUDIT' : 'AGENT'}
                </Badge>
            )}
            <Badge variant={plan.status === 'completed' ? 'default' : plan.status === 'in_progress' ? 'secondary' : plan.status === 'failed' ? 'destructive' : 'outline'}>
              {plan.status}
            </Badge>
          </div>
          {plan.description && (
            <p className="text-xs text-muted-foreground line-clamp-2">{plan.description}</p>
          )}
        </div>
      </div>

      {hasChildren && expanded && (
        <div className="flex flex-col">
          {plan.children.map(child => (
            <PlanItem key={child.id} plan={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function ToolCall({ name, args, result }: { name: string, args: any, result?: string }) {
    const [expanded, setExpanded] = useState(false);

    return (
        <div className="my-2 border rounded-md overflow-hidden bg-slate-50 dark:bg-slate-900/50">
            <div 
                className="flex items-center gap-2 p-2 cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-xs font-mono"
                onClick={() => setExpanded(!expanded)}
            >
                {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                <span className="text-purple-600 dark:text-purple-400 font-semibold">Tool Call:</span>
                <span className="font-bold">{name}</span>
                <span className="text-muted-foreground truncate max-w-[300px]">
                    {JSON.stringify(args)}
                </span>
            </div>
            
            {expanded && (
                <div className="p-2 border-t bg-white dark:bg-slate-950 text-xs font-mono overflow-auto max-h-60">
                    <div className="mb-2">
                        <div className="text-muted-foreground mb-1">Arguments:</div>
                        <pre className="bg-slate-100 dark:bg-slate-900 p-2 rounded text-blue-600 dark:text-blue-400 whitespace-pre-wrap">
                            {JSON.stringify(args, null, 2)}
                        </pre>
                    </div>
                    {result && (
                         <div>
                            <div className="text-muted-foreground mb-1">Result:</div>
                            <pre className="bg-slate-100 dark:bg-slate-900 p-2 rounded text-green-600 dark:text-green-400 whitespace-pre-wrap">
                                {result}
                            </pre>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

function ChatMessage({ msg }: { msg: any }) {
    // Check if message content contains <think> tags
    const thinkMatch = msg.content && typeof msg.content === 'string' ? msg.content.match(/<think>([\s\S]*?)<\/think>/) : null;
    let thinkContent = thinkMatch ? thinkMatch[1] : null;
    let mainContent = msg.content && typeof msg.content === 'string' ? msg.content.replace(/<think>[\s\S]*?<\/think>/, '') : msg.content;

    // Check if it's a tool call message (we stored JSON in content for tool_call role)
    if (msg.role === 'tool_call') {
        let toolCallData;
        try {
            toolCallData = JSON.parse(msg.content);
        } catch {
            toolCallData = { name: 'unknown', arguments: msg.content };
        }
        // We render it differently, but here we don't have the result easily paired unless we look ahead/behind.
        // For simplicity, we just render the call.
        // Ideally we should group them in the parent list.
        return <ToolCall key={msg.id} name={toolCallData.name} args={toolCallData.arguments} />;
    }
    
    if (msg.role === 'tool_result') {
        // This should ideally be nested inside the tool call, but for flat list:
        return (
            <div className="ml-6 mb-2 text-xs font-mono text-muted-foreground border-l-2 pl-2">
                <div className="font-semibold text-[10px] uppercase mb-1">Tool Result</div>
                <div className="line-clamp-3 hover:line-clamp-none cursor-pointer bg-slate-50 p-1 rounded">
                    {msg.content}
                </div>
            </div>
        );
    }

    return (
        <div className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} mb-4`}>
             <div className={`flex flex-col max-w-[90%] md:max-w-[80%] ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
               <span className="text-[10px] text-muted-foreground mb-1 uppercase tracking-wider font-semibold ml-1">{msg.role}</span>
               
               <div className={`rounded-lg p-3 shadow-sm ${
                  msg.role === 'user' 
                      ? 'bg-blue-600 text-white' 
                      : msg.role === 'system'
                      ? 'bg-gray-200 text-gray-800 text-xs font-mono border'
                      : 'bg-white dark:bg-slate-800 border'
               }`}>
                 {thinkContent && (
                     <div className="mb-3 p-2 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-100 dark:border-yellow-900/50 rounded text-xs text-muted-foreground italic">
                         <div className="font-semibold not-italic mb-1 flex items-center gap-1">
                             <span className="w-2 h-2 rounded-full bg-yellow-400"></span>
                             Thinking Process
                         </div>
                         <ReactMarkdown remarkPlugins={[remarkGfm]}>{thinkContent}</ReactMarkdown>
                     </div>
                 )}
                 <div className="prose prose-sm dark:prose-invert max-w-none">
                    <ReactMarkdown 
                        remarkPlugins={[remarkGfm]}
                        components={{
                            code({node, inline, className, children, ...props}: any) {
                                const match = /language-(\w+)/.exec(className || '')
                                return !inline && match ? (
                                    <SyntaxHighlighter
                                        style={oneDark}
                                        language={match[1]}
                                        PreTag="div"
                                        {...props}
                                    >
                                        {String(children).replace(/\n$/, '')}
                                    </SyntaxHighlighter>
                                ) : (
                                    <code className={className} {...props}>
                                        {children}
                                    </code>
                                )
                            }
                        }}
                    >
                        {mainContent}
                    </ReactMarkdown>
                 </div>
               </div>
               <span className="text-[10px] text-muted-foreground mt-1 mr-1">{new Date(msg.timestamp * 1000).toLocaleTimeString()}</span>
             </div>
        </div>
    );
}

export function AuditDashboard() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'plan' | 'logs' | 'memory' | 'chat' | 'findings'>('plan');
  
  const { data: status } = useQuery({ queryKey: ['auditStatus'], queryFn: auditApi.getStatus, refetchInterval: 2000 });
  const { data: plans } = useQuery({ queryKey: ['auditPlans'], queryFn: () => auditApi.getPlans(), refetchInterval: 5000 });
  const { data: logs } = useQuery({ queryKey: ['auditLogs'], queryFn: () => auditApi.getLogs(), refetchInterval: 2000 });
  const { data: memory } = useQuery({ queryKey: ['auditMemory'], queryFn: auditApi.getMemory, refetchInterval: 10000 });
  const { data: messages } = useQuery({ 
    queryKey: ['auditMessages', status?.current_session_id], 
    queryFn: () => auditApi.getMessages(status?.current_session_id), 
    refetchInterval: 2000 
  });
  const { data: notes } = useQuery({ queryKey: ['auditNotes'], queryFn: () => auditApi.getNotes(), refetchInterval: 5000 });
  const { data: findings } = useQuery({ queryKey: ['auditFindings'], queryFn: () => auditApi.getFindings(), refetchInterval: 5000 });

  const planTree = useMemo(() => plans ? buildPlanTree(plans) : [], [plans]);

  const startMutation = useMutation({
    mutationFn: auditApi.start,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auditStatus'] });
    }
  });

  const stopMutation = useMutation({
    mutationFn: auditApi.stop,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auditStatus'] });
    }
  });

  return (
    <div className="container mx-auto p-4 md:p-6 h-[calc(100vh-60px)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-6 shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Automated Audit Dashboard</h1>
          <p className="text-sm text-muted-foreground">Monitor and control the autonomous auditing agent.</p>
        </div>
        
        <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-50 dark:bg-slate-900 rounded-md border">
                <span className="text-xs text-muted-foreground uppercase font-bold tracking-wider">Status</span>
                <div className={`w-2 h-2 rounded-full ${status?.status === 'running' ? 'bg-green-500 animate-pulse' : status?.status === 'failed' ? 'bg-red-500' : 'bg-slate-300'}`} />
                <span className="text-sm font-medium">{status?.status?.toUpperCase() || 'UNKNOWN'}</span>
                {status?.current_agent && (
                    <>
                        <div className="w-px h-3 bg-border mx-1" />
                        <span className="text-xs text-muted-foreground">Agent:</span>
                        <span className="text-sm font-medium text-blue-600 dark:text-blue-400">{status.current_agent}</span>
                    </>
                )}
            </div>
            
            {status?.status === 'running' ? (
                <Button variant="destructive" size="sm" onClick={() => stopMutation.mutate()} disabled={stopMutation.isPending} className="gap-2">
                    <Square className="w-4 h-4" fill="currentColor" /> Stop Audit
                </Button>
            ) : (
                <Button size="sm" onClick={() => startMutation.mutate()} disabled={startMutation.isPending} className="gap-2">
                    <Play className="w-4 h-4" fill="currentColor" /> Start Audit
                </Button>
            )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b mb-4 shrink-0 overflow-x-auto">
        <button 
          onClick={() => setActiveTab('plan')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'plan' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <ListTodo className="w-4 h-4" /> Plan
        </button>
        <button 
          onClick={() => setActiveTab('chat')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'chat' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <MessageSquare className="w-4 h-4" /> Chat History
        </button>
        <button 
          onClick={() => setActiveTab('findings')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'findings' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <AlertTriangle className="w-4 h-4" /> Findings & Notes
        </button>
        <button 
          onClick={() => setActiveTab('logs')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'logs' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <Terminal className="w-4 h-4" /> Live Logs
        </button>
        <button 
          onClick={() => setActiveTab('memory')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'memory' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <Database className="w-4 h-4" /> Memory
        </button>
      </div>

      {/* Content Area */}
      <div className="flex-1 min-h-0 overflow-hidden">
        {activeTab === 'plan' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
            <CardContent className="flex-1 overflow-auto p-0 pr-2">
              <div className="space-y-1">
                {planTree.length > 0 ? (
                  planTree.map(plan => (
                    <PlanItem key={plan.id} plan={plan} />
                  ))
                ) : (
                  <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                    <ListTodo className="w-12 h-12 mb-4 opacity-20" />
                    <p>No audit plans found.</p>
                    <p className="text-xs mt-2">Start the audit to generate an analysis plan.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {activeTab === 'chat' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
             <CardContent className="flex-1 overflow-auto p-4 bg-slate-50 dark:bg-slate-900/50 rounded-lg border">
                 <div className="space-y-6">
                 {messages?.map((msg) => (
                    <ChatMessage key={msg.id} msg={msg} />
                 ))}
                 {!messages?.length && (
                    <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                        <MessageSquare className="w-12 h-12 mb-4 opacity-20" />
                        <p>No conversation history.</p>
                    </div>
                 )}
                 </div>
              </CardContent>
          </Card>
        )}
        
        {activeTab === 'findings' && (
          <div className="h-full grid grid-cols-1 md:grid-cols-2 gap-4 overflow-hidden">
              <Card className="h-full flex flex-col">
                  <div className="p-4 border-b bg-slate-50 dark:bg-slate-900/50 font-semibold flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-red-500" /> Security Findings
                  </div>
                  <CardContent className="flex-1 overflow-auto p-4">
                      {findings && findings.length > 0 ? (
                          <div className="space-y-4">
                              {findings.map(finding => (
                                  <div key={finding.finding_id} className="border rounded-lg p-3 shadow-sm">
                                      <div className="flex items-center justify-between mb-2">
                                          <div className="font-semibold text-sm">{finding.category}</div>
                                          <Badge variant={finding.severity === 'critical' ? 'destructive' : finding.severity === 'high' ? 'destructive' : finding.severity === 'medium' ? 'warning' : 'info'}>
                                              {finding.severity}
                                          </Badge>
                                      </div>
                                      <p className="text-xs text-muted-foreground mb-2">{finding.description}</p>
                                      {finding.function_name && (
                                          <div className="flex items-center gap-2 text-xs font-mono bg-slate-100 dark:bg-slate-800 p-1 rounded w-fit mb-2">
                                              <Code className="w-3 h-3" />
                                              {finding.function_name} @ {finding.address}
                                          </div>
                                      )}
                                  </div>
                              ))}
                          </div>
                      ) : (
                          <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                              <p>No security findings yet.</p>
                          </div>
                      )}
                  </CardContent>
              </Card>
              
              <Card className="h-full flex flex-col">
                  <div className="p-4 border-b bg-slate-50 dark:bg-slate-900/50 font-semibold flex items-center gap-2">
                      <StickyNote className="w-4 h-4 text-blue-500" /> Analysis Notes
                  </div>
                  <CardContent className="flex-1 overflow-auto p-4">
                      {notes && notes.length > 0 ? (
                          <div className="space-y-4">
                              {notes.map(note => (
                                  <div key={note.note_id} className="border rounded-lg p-3 shadow-sm bg-yellow-50/50 dark:bg-yellow-900/10">
                                      <div className="flex items-center justify-between mb-2">
                                          <div className="font-semibold text-xs text-muted-foreground uppercase">{note.note_type}</div>
                                          <span className="text-[10px] text-muted-foreground">{new Date(note.created_at).toLocaleString()}</span>
                                      </div>
                                      <p className="text-sm whitespace-pre-wrap">{note.content}</p>
                                      {note.tags && note.tags.length > 0 && (
                                          <div className="flex flex-wrap gap-1 mt-2">
                                              {note.tags.map(tag => (
                                                  <span key={tag} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-1.5 py-0.5 rounded text-slate-700 dark:text-slate-300">#{tag}</span>
                                              ))}
                                          </div>
                                      )}
                                  </div>
                              ))}
                          </div>
                      ) : (
                          <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                              <p>No analysis notes yet.</p>
                          </div>
                      )}
                  </CardContent>
              </Card>
          </div>
        )}

        {activeTab === 'logs' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
            <CardContent className="flex-1 bg-black rounded-lg p-0 overflow-hidden border border-slate-800">
               <div className="h-full overflow-auto p-4 font-mono text-xs text-green-400 space-y-1">
               {logs?.map((log) => (
                 <div key={log.id} className="break-all hover:bg-white/5 px-1 rounded">
                   <span className="opacity-50 mr-3 text-blue-400">[{new Date(log.timestamp * 1000).toLocaleTimeString()}]</span>
                   {log.message}
                 </div>
               ))}
               {!logs?.length && (
                   <div className="flex flex-col items-center justify-center h-full text-slate-600">
                       <Terminal className="w-12 h-12 mb-4 opacity-20" />
                       <p>Waiting for logs...</p>
                   </div>
               )}
               </div>
            </CardContent>
          </Card>
        )}

        {activeTab === 'memory' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
            <CardContent className="flex-1 overflow-auto p-0">
              {memory && Object.keys(memory).length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {Object.entries(memory).map(([key, value]) => (
                          <div key={key} className="bg-card border p-4 rounded-lg shadow-sm">
                              <div className="flex items-center gap-2 mb-2 pb-2 border-b">
                                  <Database className="w-3 h-3 text-muted-foreground" />
                                  <div className="font-semibold text-sm text-primary truncate" title={key}>{key}</div>
                              </div>
                              <pre className="text-xs whitespace-pre-wrap text-muted-foreground font-mono bg-slate-50 dark:bg-slate-900 p-2 rounded max-h-40 overflow-auto">
                                  {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                              </pre>
                          </div>
                      ))}
                  </div>
              ) : (
                  <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                      <Database className="w-12 h-12 mb-4 opacity-20" />
                      <p>Memory is empty.</p>
                  </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
