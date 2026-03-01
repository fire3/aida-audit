import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
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
    const { t } = useTranslation();
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
                        {t('plan_view.audit_strategy')}
                    </h3>
                    <div className="flex gap-1">
                        <Button
                            variant="ghost"
                            size="icon"
                            className="h-6 w-6"
                            onClick={() => setIsMacroModalOpen(true)}
                            title={t('plan_view.add_strategy')}
                        >
                            <Plus className="w-4 h-4" />
                        </Button>
                        <Button 
                            variant="ghost" 
                            size="icon" 
                            className="h-6 w-6" 
                            onClick={() => setIsTaskModalOpen(true)}
                            title={t('plan_view.add_task')}
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
                                <div className="text-[10px] uppercase font-bold text-muted-foreground mb-1">{t('plan_view.tasks')}</div>
                                
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
                                    <div className="text-[10px] text-muted-foreground italic">{t('plan_view.no_tasks_assigned')}</div>
                                )}
                            </div>
                        </div>
                    ))}
                    {macroPlans.length === 0 && (
                        <div className="text-center text-muted-foreground py-8">
                            {t('plan_view.no_audit_plans')}
                        </div>
                    )}
                </div>
            </div>

            <div className="flex-1 overflow-auto">
                 <h3 className="font-semibold mb-4 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-orange-500" />
                    {t('plan_view.task_execution')}
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
                                        {task.description || t('plan_view.no_description')}
                                    </p>
                                </div>

                                <div className="flex items-center justify-between text-[10px] text-muted-foreground mt-2 pt-2 border-t border-dashed border-slate-100 dark:border-slate-800">
                                    <div className="flex items-center gap-3 overflow-hidden">
                                        {parentPlan && (
                                            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300 border border-purple-100 dark:border-purple-800/30 shrink-0 max-w-[200px]">
                                                <ListTodo className="w-3 h-3 shrink-0" />
                                                <span className="font-medium truncate" title={parentPlan.title}>
                                                    {t('plan_view.parent')}: {parentPlan.title}
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
                            <p>{t('plan_view.no_tasks_generated')}</p>
                            <p className="text-xs mt-2">{t('plan_view.set_requirements_hint')}</p>
                        </div>
                    )}
                </div>
            </div>

            <Modal
                isOpen={isMacroModalOpen}
                onClose={() => setIsMacroModalOpen(false)}
                title={t('plan_view.create_strategy')}
            >
                <div className="space-y-4">
                    <div className="space-y-2">
                        <label className="text-sm font-medium">{t('plan_view.title')}</label>
                        <Input
                            value={newMacroTitle}
                            onChange={(e) => setNewMacroTitle(e.target.value)}
                            placeholder={t('plan_view.title_placeholder')}
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">{t('plan_view.description_label')}</label>
                        <Textarea
                            value={newMacroDesc}
                            onChange={(e) => setNewMacroDesc(e.target.value)}
                            placeholder={t('plan_view.description_placeholder')}
                            className="h-24"
                        />
                    </div>
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="ghost" onClick={() => setIsMacroModalOpen(false)}>{t('plan_view.cancel')}</Button>
                        <Button onClick={handleCreateMacroPlan} disabled={createMacroPlanMutation.isPending || !newMacroTitle || !newMacroDesc}>
                            {createMacroPlanMutation.isPending ? t('plan_view.creating') : t('plan_view.create_strategy_btn')}
                        </Button>
                    </div>
                </div>
            </Modal>

            <Modal
                isOpen={isTaskModalOpen}
                onClose={() => setIsTaskModalOpen(false)}
                title={t('plan_view.create_task')}
            >
                <div className="space-y-4">
                    <div className="space-y-2">
                        <label className="text-sm font-medium">{t('plan_view.task_type')}</label>
                        <Select
                            value={newTaskType}
                            onChange={(e) => setNewTaskType(e.target.value as 'ANALYSIS' | 'VERIFICATION')}
                        >
                            <option value="ANALYSIS">{t('plan_view.analysis_task')}</option>
                            <option value="VERIFICATION">{t('plan_view.verification_task')}</option>
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">{t('plan_view.parent_strategy')}</label>
                        <Select
                            value={selectedPlanId}
                            onChange={(e) => setSelectedPlanId(e.target.value)}
                        >
                            <option value="" disabled>{t('plan_view.select_strategy')}</option>
                            {macroPlans.map(p => (
                                <option key={p.id} value={p.id}>{p.title}</option>
                            ))}
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">{t('plan_view.target_binary')}</label>
                        <Select
                            value={newTaskBinary}
                            onChange={(e) => setNewTaskBinary(e.target.value)}
                        >
                            <option value="" disabled>{t('plan_view.select_binary')}</option>
                            {binaries?.map((b: { binary_name: string }) => (
                                <option key={b.binary_name} value={b.binary_name}>{b.binary_name}</option>
                            ))}
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">{t('plan_view.title')}</label>
                        <Input
                            value={newTaskTitle}
                            onChange={(e) => setNewTaskTitle(e.target.value)}
                            placeholder={t('plan_view.title_placeholder_task')}
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">{t('plan_view.description_task')}</label>
                        <Textarea
                            value={newTaskDesc}
                            onChange={(e) => setNewTaskDesc(e.target.value)}
                            placeholder={t('plan_view.description_placeholder_task')}
                            className="h-24"
                        />
                    </div>
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="ghost" onClick={() => setIsTaskModalOpen(false)}>{t('plan_view.cancel')}</Button>
                        <Button onClick={handleCreateTask} disabled={createTaskMutation.isPending || !newTaskTitle || !newTaskDesc || !selectedPlanId || !newTaskBinary}>
                            {createTaskMutation.isPending ? t('plan_view.creating') : t('plan_view.create_task_btn')}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
}
