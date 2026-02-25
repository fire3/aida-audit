import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, useMemo } from 'react';
import { auditApi, projectApi, type AuditPlan } from '../api/client';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Textarea } from '../components/ui/textarea';
import { Select } from '../components/ui/select';
import { Modal } from '../components/ui/modal';
import { StatusIcon, Badge } from './AuditBadge';
import { UserPromptConfig } from './UserPromptConfig';
import { ListTodo, Plus, Terminal, Code, Clock, ShieldCheck } from 'lucide-react';

export function PlanView({ plans }: { plans: AuditPlan[] }) {
    const queryClient = useQueryClient();
    const macroPlans = useMemo(() => plans.filter(p => p.plan_type === 'audit_plan'), [plans]);
    const agentTasks = useMemo(() => 
        plans.filter(p => p.plan_type === 'agent_plan').sort((a, b) => b.id - a.id), 
        [plans]
    );
    const verificationTasks = useMemo(() => 
        plans.filter(p => p.plan_type === 'verification_plan').sort((a, b) => b.id - a.id),
        [plans]
    );

    const allExecutionTasks = useMemo(() => 
        [...agentTasks, ...verificationTasks].sort((a, b) => b.id - a.id),
        [agentTasks, verificationTasks]
    );

    const [isMacroModalOpen, setIsMacroModalOpen] = useState(false);
    const [newMacroTitle, setNewMacroTitle] = useState("");
    const [newMacroDesc, setNewMacroDesc] = useState("");

    const [isTaskModalOpen, setIsTaskModalOpen] = useState(false);
    const [newTaskTitle, setNewTaskTitle] = useState("");
    const [newTaskDesc, setNewTaskDesc] = useState("");
    const [selectedPlanId, setSelectedPlanId] = useState<string>("");
    const [newTaskBinary, setNewTaskBinary] = useState("");
    const [newTaskType, setNewTaskType] = useState<'ANALYSIS' | 'VERIFICATION'>('ANALYSIS');

    const { data: binaries } = useQuery({
        queryKey: ['projectBinaries'],
        queryFn: () => projectApi.listBinaries(0, 100),
        staleTime: 30000
    });

    const createMacroPlanMutation = useMutation({
        mutationFn: auditApi.createMacroPlan,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['auditMacroPlans'] });
            setIsMacroModalOpen(false);
            setNewMacroTitle("");
            setNewMacroDesc("");
        }
    });

    const createTaskMutation = useMutation({
        mutationFn: auditApi.createTask,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['auditTasks'] });
            setIsTaskModalOpen(false);
            setNewTaskTitle("");
            setNewTaskDesc("");
            setSelectedPlanId("");
            setNewTaskBinary("");
            setNewTaskType('ANALYSIS');
        }
    });

    const handleCreateMacroPlan = () => {
        if (!newMacroTitle || !newMacroDesc) return;
        createMacroPlanMutation.mutate({
            title: newMacroTitle,
            description: newMacroDesc
        });
    };

    const handleCreateTask = () => {
        if (!newTaskTitle || !newTaskDesc || !selectedPlanId || !newTaskBinary) return;
        createTaskMutation.mutate({
            title: newTaskTitle,
            description: newTaskDesc,
            plan_id: parseInt(selectedPlanId),
            binary_name: newTaskBinary,
            task_type: newTaskType
        });
    };

    return (
        <div className="h-full flex gap-4">
            <div className="w-1/3 border-r pr-4 overflow-auto">
                <UserPromptConfig />
                <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold flex items-center gap-2">
                        <ListTodo className="w-4 h-4 text-purple-500" />
                        Audit Strategy
                    </h3>
                    <div className="flex gap-1">
                        <Button 
                            variant="ghost" 
                            size="icon" 
                            className="h-6 w-6" 
                            onClick={() => setIsMacroModalOpen(true)}
                            title="Add Audit Strategy (Macro Plan)"
                        >
                            <Plus className="w-4 h-4" />
                        </Button>
                        <Button 
                            variant="ghost" 
                            size="icon" 
                            className="h-6 w-6" 
                            onClick={() => setIsTaskModalOpen(true)}
                            title="Add Task"
                            disabled={macroPlans.length === 0}
                        >
                            <ListTodo className="w-4 h-4" />
                        </Button>
                    </div>
                </div>
                
                <div className="space-y-4">
                    {macroPlans.map(plan => (
                        <div key={plan.id} className="border rounded-lg p-3 bg-purple-50/30 dark:bg-purple-900/10">
                            <div className="flex items-center justify-between mb-2">
                                <span className="font-medium text-sm">{plan.title}</span>
                                <StatusIcon status={plan.status} />
                            </div>
                            <p className="text-xs text-muted-foreground mb-2">{plan.description}</p>
                            
                            <div className="space-y-1 mt-3 pl-2 border-l-2 border-slate-200 dark:border-slate-800">
                                <div className="text-[10px] uppercase font-bold text-muted-foreground mb-1">Tasks</div>
                                
                                {agentTasks.filter(t => t.plan_id === plan.id).map(task => (
                                    <div key={task.id} className="flex items-center gap-2 text-xs py-1">
                                        <StatusIcon status={task.status} />
                                        <span className={`${task.status === 'completed' ? 'line-through text-muted-foreground' : ''}`}>
                                            {task.title}
                                        </span>
                                    </div>
                                ))}

                                {verificationTasks.filter(t => t.plan_id === plan.id).map(task => (
                                    <div key={task.id} className="flex items-center gap-2 text-xs py-1">
                                        <StatusIcon status={task.status} />
                                        <ShieldCheck className="w-3 h-3 text-blue-500" />
                                        <span className={`${task.status === 'completed' ? 'line-through text-muted-foreground' : ''}`}>
                                            {task.title}
                                        </span>
                                    </div>
                                ))}

                                {agentTasks.filter(t => t.plan_id === plan.id).length === 0 && verificationTasks.filter(t => t.plan_id === plan.id).length === 0 && (
                                    <div className="text-[10px] text-muted-foreground italic">No tasks assigned yet</div>
                                )}
                            </div>
                        </div>
                    ))}
                    {macroPlans.length === 0 && (
                        <div className="text-center text-muted-foreground py-8">
                            No audit plans defined.
                        </div>
                    )}
                </div>
            </div>

            <div className="flex-1 overflow-auto">
                 <h3 className="font-semibold mb-4 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-orange-500" />
                    Task Execution Stream
                </h3>
                <div className="space-y-3">
                    {allExecutionTasks.length > 0 ? (
                        allExecutionTasks.map(task => {
                            const parentPlan = macroPlans.find(p => p.id === task.plan_id);
                            const isVerification = task.plan_type === 'verification_plan';
                            return (
                             <div key={task.id} className={`group relative border rounded-lg p-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-all hover:shadow-sm bg-white dark:bg-slate-900 ${isVerification ? 'border-l-4 border-l-blue-400' : ''}`}>
                                <div className="flex items-center justify-between gap-3 mb-2">
                                    <div className="flex items-center gap-2 overflow-hidden">
                                        <div className={`flex items-center justify-center w-6 h-6 rounded-full shrink-0 border border-slate-200 dark:border-slate-700 ${isVerification ? 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400' : 'bg-slate-100 dark:bg-slate-800 text-slate-500'}`}>
                                            {isVerification ? <ShieldCheck className="w-3 h-3" /> : <span className="text-[10px] font-mono font-bold">#{task.id}</span>}
                                        </div>
                                        <h4 className="font-semibold text-sm truncate text-slate-800 dark:text-slate-200" title={task.title}>
                                            {task.title}
                                        </h4>
                                    </div>
                                    <div className="flex items-center gap-2 shrink-0">
                                         <StatusIcon status={task.status} />
                                         <Badge variant={task.status === 'completed' ? 'default' : task.status === 'in_progress' ? 'secondary' : task.status === 'failed' ? 'destructive' : 'outline'}>
                                            {task.status}
                                        </Badge>
                                    </div>
                                </div>

                                <div className="bg-slate-50 dark:bg-slate-950/50 rounded-md p-2.5 mb-2 border border-slate-100 dark:border-slate-800 h-24 overflow-y-auto custom-scrollbar">
                                    <p className="text-xs text-muted-foreground whitespace-pre-wrap leading-relaxed font-mono">
                                        {task.description || "No description provided."}
                                    </p>
                                </div>

                                <div className="flex items-center justify-between text-[10px] text-muted-foreground mt-2 pt-2 border-t border-dashed border-slate-100 dark:border-slate-800">
                                    <div className="flex items-center gap-3 overflow-hidden">
                                        {parentPlan && (
                                            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300 border border-purple-100 dark:border-purple-800/30 shrink-0 max-w-[200px]">
                                                <ListTodo className="w-3 h-3 shrink-0" />
                                                <span className="font-medium truncate" title={parentPlan.title}>
                                                    Parent: {parentPlan.title}
                                                </span>
                                            </div>
                                        )}
                                        
                                        {task.binary_name && (
                                            <div className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 shrink-0">
                                                <Code className="w-3 h-3" />
                                                <span className="font-mono">{task.binary_name}</span>
                                            </div>
                                        )}
                                    </div>

                                    <div className="flex items-center gap-1 opacity-70 shrink-0 ml-2">
                                        <Clock className="w-3 h-3" />
                                        <span>{new Date(task.updated_at * 1000).toLocaleString()}</span>
                                    </div>
                                </div>
                             </div>
                            );
                        })
                    ) : (
                        <div className="flex flex-col items-center justify-center h-64 text-muted-foreground border rounded-lg bg-slate-50/50 dark:bg-slate-900/20 border-dashed">
                            <ListTodo className="w-12 h-12 mb-4 opacity-20" />
                            <p>No tasks generated yet.</p>
                            <p className="text-xs mt-2">Set your requirements on the left and start the audit.</p>
                        </div>
                    )}
                </div>
            </div>

            <Modal
                isOpen={isMacroModalOpen}
                onClose={() => setIsMacroModalOpen(false)}
                title="Create Audit Strategy (Macro Plan)"
            >
                <div className="space-y-4">
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Title</label>
                        <Input 
                            value={newMacroTitle} 
                            onChange={(e) => setNewMacroTitle(e.target.value)} 
                            placeholder="e.g., Attack Surface Enumeration"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Description</label>
                        <Textarea 
                            value={newMacroDesc} 
                            onChange={(e) => setNewMacroDesc(e.target.value)} 
                            placeholder="Describe the high-level goal of this phase..."
                            className="h-24"
                        />
                    </div>
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="ghost" onClick={() => setIsMacroModalOpen(false)}>Cancel</Button>
                        <Button onClick={handleCreateMacroPlan} disabled={createMacroPlanMutation.isPending || !newMacroTitle || !newMacroDesc}>
                            {createMacroPlanMutation.isPending ? "Creating..." : "Create Strategy"}
                        </Button>
                    </div>
                </div>
            </Modal>

            <Modal
                isOpen={isTaskModalOpen}
                onClose={() => setIsTaskModalOpen(false)}
                title="Create Task"
            >
                <div className="space-y-4">
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Task Type</label>
                        <Select 
                            value={newTaskType}
                            onChange={(e) => setNewTaskType(e.target.value as 'ANALYSIS' | 'VERIFICATION')}
                        >
                            <option value="ANALYSIS">Analysis Task (Agent)</option>
                            <option value="VERIFICATION">Verification Task</option>
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Parent Strategy</label>
                        <Select 
                            value={selectedPlanId}
                            onChange={(e) => setSelectedPlanId(e.target.value)}
                        >
                            <option value="" disabled>Select a strategy...</option>
                            {macroPlans.map(p => (
                                <option key={p.id} value={p.id}>{p.title}</option>
                            ))}
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Target Binary</label>
                        <Select 
                            value={newTaskBinary}
                            onChange={(e) => setNewTaskBinary(e.target.value)}
                        >
                            <option value="" disabled>Select a binary...</option>
                            {binaries?.map((b: { binary_name: string }) => (
                                <option key={b.binary_name} value={b.binary_name}>{b.binary_name}</option>
                            ))}
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Title</label>
                        <Input 
                            value={newTaskTitle} 
                            onChange={(e) => setNewTaskTitle(e.target.value)} 
                            placeholder="e.g., Analyze login function"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Description</label>
                        <Textarea 
                            value={newTaskDesc} 
                            onChange={(e) => setNewTaskDesc(e.target.value)} 
                            placeholder="Detailed instructions for the agent..."
                            className="h-24"
                        />
                    </div>
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="ghost" onClick={() => setIsTaskModalOpen(false)}>Cancel</Button>
                        <Button onClick={handleCreateTask} disabled={createTaskMutation.isPending || !newTaskTitle || !newTaskDesc || !selectedPlanId || !newTaskBinary}>
                            {createTaskMutation.isPending ? "Creating..." : "Create Task"}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
}
