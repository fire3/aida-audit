import { useQuery } from '@tanstack/react-query';
import { useState, useEffect } from 'react';
import { auditApi } from '../api/client';
import { Button } from '../components/ui/button';
import { MessageSquare } from 'lucide-react';
import { useTranslation } from 'react-i18next';

export function UserPromptConfig() {
    const { t } = useTranslation();
    const [isEditing, setIsEditing] = useState(false);
    const [prompt, setPrompt] = useState("");
    const [loading, setLoading] = useState(false);

    const { data, refetch } = useQuery({
        queryKey: ['userPrompt'],
        queryFn: auditApi.getUserPrompt,
        refetchOnWindowFocus: false
    });

    useEffect(() => {
        if (data) {
            setPrompt(data.content);
        }
    }, [data]);

    const handleSave = async () => {
        setLoading(true);
        try {
            await auditApi.updateUserPrompt(prompt);
            await refetch();
            setIsEditing(false);
        } catch (error) {
            console.error("Failed to save prompt", error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="mb-4 border rounded-lg p-3 bg-white dark:bg-slate-900 shadow-sm">
            <div className="flex items-center justify-between mb-2">
                <h3 className="font-semibold text-sm flex items-center gap-2">
                    <MessageSquare className="w-4 h-4 text-blue-500" />
                    {t('plan_view.user_requirements')}
                </h3>
                {!isEditing && (
                    <Button variant="ghost" size="sm" onClick={() => setIsEditing(true)} className="h-6 text-xs">
                        {t('plan_view.edit')}
                    </Button>
                )}
            </div>

            {isEditing ? (
                <div className="space-y-2">
                    <textarea
                        className="w-full text-xs p-2 border rounded bg-slate-50 dark:bg-slate-800 min-h-[60px] focus:outline-none focus:ring-1 focus:ring-blue-500"
                        placeholder={t('plan_view.requirements_placeholder')}
                        value={prompt}
                        onChange={(e) => setPrompt(e.target.value)}
                    />
                    <div className="flex justify-end gap-2">
                        <Button variant="ghost" size="sm" onClick={() => {
                            setIsEditing(false);
                            setPrompt(data?.content || "");
                        }} className="h-7 text-xs">
                            {t('plan_view.cancel')}
                        </Button>
                        <Button size="sm" onClick={handleSave} disabled={loading} className="h-7 text-xs">
                            {loading ? t('plan_view.saving') : t('plan_view.save')}
                        </Button>
                    </div>
                </div>
            ) : (
                <div className="text-xs text-muted-foreground">
                    {prompt ? (
                        <p className="whitespace-pre-wrap">{prompt}</p>
                    ) : (
                        <p className="italic opacity-70">{t('plan_view.no_requirements')}</p>
                    )}
                </div>
            )}
        </div>
    );
}
