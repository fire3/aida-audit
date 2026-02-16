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
  Square
} from 'lucide-react';

function Badge({ children, variant }: { children: React.ReactNode, variant: string }) {
    const colors = {
        default: "bg-green-100 text-green-800 border border-green-200",
        secondary: "bg-blue-100 text-blue-800 border border-blue-200",
        outline: "bg-gray-100 text-gray-800 border border-gray-200",
        destructive: "bg-red-100 text-red-800 border border-red-200"
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

export function AuditDashboard() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'plan' | 'logs' | 'memory' | 'chat'>('plan');
  
  const { data: status } = useQuery({ queryKey: ['auditStatus'], queryFn: auditApi.getStatus, refetchInterval: 2000 });
  const { data: plans } = useQuery({ queryKey: ['auditPlans'], queryFn: () => auditApi.getPlans(), refetchInterval: 5000 });
  const { data: logs } = useQuery({ queryKey: ['auditLogs'], queryFn: () => auditApi.getLogs(), refetchInterval: 2000 });
  const { data: memory } = useQuery({ queryKey: ['auditMemory'], queryFn: auditApi.getMemory, refetchInterval: 10000 });
  const { data: messages } = useQuery({ queryKey: ['auditMessages'], queryFn: () => auditApi.getMessages(), refetchInterval: 2000 });

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
      <div className="flex items-center gap-1 border-b mb-4 shrink-0">
        <button 
          onClick={() => setActiveTab('plan')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === 'plan' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <ListTodo className="w-4 h-4" /> Plan
        </button>
        <button 
          onClick={() => setActiveTab('chat')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === 'chat' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <MessageSquare className="w-4 h-4" /> Chat History
        </button>
        <button 
          onClick={() => setActiveTab('logs')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === 'logs' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <Terminal className="w-4 h-4" /> Live Logs
        </button>
        <button 
          onClick={() => setActiveTab('memory')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === 'memory' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
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
                   <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                     <div className={`flex flex-col max-w-[85%] ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                       <span className="text-[10px] text-muted-foreground mb-1 uppercase tracking-wider font-semibold ml-1">{msg.role}</span>
                       <div className={`rounded-lg p-3 shadow-sm ${
                          msg.role === 'user' 
                              ? 'bg-blue-600 text-white' 
                              : msg.role === 'system'
                              ? 'bg-gray-200 text-gray-800 text-xs font-mono border'
                              : 'bg-white dark:bg-slate-800 border'
                       }`}>
                         <div className="whitespace-pre-wrap text-sm">{msg.content}</div>
                       </div>
                       <span className="text-[10px] text-muted-foreground mt-1 mr-1">{new Date(msg.timestamp * 1000).toLocaleTimeString()}</span>
                     </div>
                   </div>
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
