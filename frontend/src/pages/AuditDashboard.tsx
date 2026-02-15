import { useQuery } from '@tanstack/react-query';
import { auditApi } from '../api/client';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';

function Badge({ children, variant }: { children: React.ReactNode, variant: string }) {
    const colors = {
        default: "bg-green-100 text-green-800 border border-green-200",
        secondary: "bg-blue-100 text-blue-800 border border-blue-200",
        outline: "bg-gray-100 text-gray-800 border border-gray-200",
        destructive: "bg-red-100 text-red-800 border border-red-200"
    };
    const style = colors[variant as keyof typeof colors] || colors.outline;
    return (
        <span className={`px-2 py-1 rounded-full text-xs font-medium ${style}`}>
            {children}
        </span>
    )
}

export function AuditDashboard() {
  const { data: plans } = useQuery({ queryKey: ['auditPlans'], queryFn: () => auditApi.getPlans(), refetchInterval: 5000 });
  const { data: logs } = useQuery({ queryKey: ['auditLogs'], queryFn: () => auditApi.getLogs(), refetchInterval: 2000 });
  const { data: memory } = useQuery({ queryKey: ['auditMemory'], queryFn: auditApi.getMemory, refetchInterval: 10000 });
  const { data: messages } = useQuery({ queryKey: ['auditMessages'], queryFn: () => auditApi.getMessages(), refetchInterval: 2000 });

  return (
    <div className="container mx-auto p-6 space-y-6">
      <h1 className="text-3xl font-bold tracking-tight">Automated Audit Dashboard</h1>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Plans */}
        <Card className="flex flex-col h-[500px]">
          <CardHeader>
            <CardTitle>Audit Plan</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-auto">
            <div className="space-y-4">
              {plans?.map((plan) => (
                <div key={plan.id} className="flex flex-col space-y-2 border-b pb-3 last:border-0">
                  <div className="flex items-center justify-between">
                    <h3 className="font-medium text-sm">{plan.title}</h3>
                    <Badge variant={plan.status === 'completed' ? 'default' : plan.status === 'in_progress' ? 'secondary' : plan.status === 'failed' ? 'destructive' : 'outline'}>
                      {plan.status}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{plan.description}</p>
                </div>
              ))}
              {!plans?.length && <div className="text-center text-muted-foreground py-10">No active audit plans. Run 'aida-cli audit' to start.</div>}
            </div>
          </CardContent>
        </Card>

        {/* Live Logs */}
        <Card className="flex flex-col h-[500px]">
          <CardHeader>
            <CardTitle>Live Logs</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 bg-black rounded-b-lg p-0 overflow-hidden">
             <div className="h-full overflow-auto p-4 font-mono text-xs text-green-400 space-y-1">
             {logs?.map((log) => (
               <div key={log.id} className="break-all">
                 <span className="opacity-50 mr-2">[{new Date(log.timestamp * 1000).toLocaleTimeString()}]</span>
                 {log.message}
               </div>
             ))}
             {!logs?.length && <span className="text-gray-500">Waiting for logs...</span>}
             </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Memory */}
        <Card className="flex flex-col h-[600px]">
          <CardHeader>
            <CardTitle>Agent Memory</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-auto">
            {memory && Object.keys(memory).length > 0 ? (
                <div className="space-y-2">
                    {Object.entries(memory).map(([key, value]) => (
                        <div key={key} className="bg-muted p-3 rounded-md">
                            <div className="font-semibold text-xs text-primary mb-1">{key}</div>
                            <pre className="text-xs whitespace-pre-wrap text-muted-foreground">
                                {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                            </pre>
                        </div>
                    ))}
                </div>
            ) : (
                <div className="text-center text-muted-foreground py-10">Memory is empty.</div>
            )}
          </CardContent>
        </Card>

        {/* Chat History */}
        <Card className="flex flex-col h-[600px]">
          <CardHeader>
            <CardTitle>Conversation History</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-auto p-4 bg-slate-50 dark:bg-slate-900/50">
             <div className="space-y-4">
             {messages?.map((msg) => (
               <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                 <div className={`max-w-[85%] rounded-lg p-3 shadow-sm ${
                    msg.role === 'user' 
                        ? 'bg-blue-600 text-white' 
                        : msg.role === 'system'
                        ? 'bg-gray-200 text-gray-800 text-xs font-mono'
                        : 'bg-white dark:bg-slate-800 border'
                 }`}>
                   <div className="text-[10px] opacity-70 mb-1 font-bold uppercase tracking-wider">{msg.role}</div>
                   <div className="whitespace-pre-wrap text-sm">{msg.content}</div>
                 </div>
               </div>
             ))}
             {!messages?.length && <div className="text-center text-muted-foreground">No messages recorded.</div>}
             </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
