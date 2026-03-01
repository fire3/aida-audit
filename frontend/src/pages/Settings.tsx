import { useState, useEffect } from 'react';
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Select } from "../components/ui/select";
import { auditApi, configApi, scheduleApi, type ScheduleConfig, type LlmConfig } from '../api/client';
import { Bot, Clock, Globe, Settings as SettingsIcon } from 'lucide-react';

function TimePicker({ 
    label, 
    value, 
    onChange, 
    disabled 
}: { 
    label: string; 
    value: string; 
    onChange: (value: string) => void; 
    disabled?: boolean;
}) {
    const [hours = '00', minutes = '00'] = (value || '00:00').split(':');
    
    const hourOptions = Array.from({ length: 24 }, (_, i) => 
        i.toString().padStart(2, '0')
    );
    const minuteOptions = ['00', '15', '30', '45'];
    
    return (
        <div className="space-y-2">
            <label className="text-sm font-medium leading-none">{label}</label>
            <div className="flex gap-2">
                <Select
                    value={hours}
                    onChange={(e) => onChange(`${e.target.value}:${minutes}`)}
                    disabled={disabled}
                    className="w-20"
                >
                    {hourOptions.map(h => (
                        <option key={h} value={h}>{h}</option>
                    ))}
                </Select>
                <span className="self-center">:</span>
                <Select
                    value={minutes}
                    onChange={(e) => onChange(`${hours}:${e.target.value}`)}
                    disabled={disabled}
                    className="w-20"
                >
                    {minuteOptions.map(m => (
                        <option key={m} value={m}>{m}</option>
                    ))}
                </Select>
            </div>
        </div>
    );
}

type TabType = 'llm' | 'schedule' | 'language';

export function Settings() {
    const [activeTab, setActiveTab] = useState<TabType>('llm');
    const [config, setConfig] = useState<LlmConfig>({
        base_url: '',
        api_key: '',
        model: ''
    });
    const [schedule, setSchedule] = useState<ScheduleConfig>({
        enabled: false,
        periods: [{ start: '09:00', stop: '18:00' }]
    });
    const [reportLanguage, setReportLanguage] = useState("Chinese");
    const [isLoading, setIsLoading] = useState(false);
    const [availableModels, setAvailableModels] = useState<string[]>([]);
    const [status, setStatus] = useState<{ type: 'success' | 'error' | null, message: string }>({ type: null, message: '' });

    useEffect(() => {
        fetchConfig();
        fetchSchedule();
        fetchReportLanguage();
    }, []);

    const fetchSchedule = async () => {
        try {
            const data = await scheduleApi.get();
            setSchedule({
                enabled: data.enabled ?? false,
                periods: data.periods?.length ? data.periods : [{ start: '09:00', stop: '18:00' }]
            });
        } catch (error) {
            console.error('Failed to fetch schedule:', error);
        }
    };

    const handleSaveSchedule = async () => {
        setIsLoading(true);
        try {
            await scheduleApi.update(schedule);
            setStatus({ type: 'success', message: "Schedule updated successfully" });
        } catch (error: any) {
            setStatus({ type: 'error', message: error.message || "Failed to update schedule" });
        } finally {
            setIsLoading(false);
        }
    };

    const fetchReportLanguage = async () => {
        try {
            const data = await auditApi.getReportLanguage();
            setReportLanguage(data.language || "Chinese");
        } catch (error) {
            console.error('Failed to fetch report language:', error);
        }
    };

    const handleSaveReportLanguage = async () => {
        setIsLoading(true);
        try {
            await auditApi.updateReportLanguage(reportLanguage);
            setStatus({ type: 'success', message: "Report language updated successfully" });
        } catch (error) {
            setStatus({ type: 'error', message: "Failed to update report language" });
        } finally {
            setIsLoading(false);
        }
    };


    const fetchConfig = async () => {
        try {
            const data = await configApi.get();
            setConfig(data);
            if (data.base_url && data.api_key && !data.api_key.includes('*')) {
                fetchModels(data.base_url, data.api_key, data.model || '');
            }
        } catch (error) {
            console.error(error);
            setStatus({ type: 'error', message: "Failed to load configuration" });
        }
    };

    const fetchModels = async (baseUrl: string, apiKey: string, model: string) => {
        if (!apiKey || apiKey.includes('*')) {
            console.warn('Cannot fetch models: API key is masked or empty');
            return [];
        }

        try {
            const data = await configApi.validate({
                base_url: baseUrl,
                api_key: apiKey,
                model: model || 'gpt-4o'
            });
            if (data.models) {
                setAvailableModels(data.models);
                return data.models;
            }
        } catch (error: any) {
            console.error('Failed to list models:', error.message);
        }
        return [];
    };

    const handleSave = async () => {
        setIsLoading(true);
        setStatus({ type: null, message: '' });
        try {
            await configApi.update(config);
            setStatus({ type: 'success', message: "Configuration saved successfully" });

            const data = await configApi.get();
            setConfig(data);

            const originalApiKey = config.api_key;
            const originalBaseUrl = config.base_url;
            const originalModel = config.model;

            if (originalApiKey && !originalApiKey.includes('*') && originalBaseUrl) {
                setTimeout(() => {
                    fetchModels(originalBaseUrl, originalApiKey, originalModel || '');
                }, 500);
            }
        } catch (error: any) {
            setStatus({ type: 'error', message: error.message });
        } finally {
            setIsLoading(false);
        }
    };

    const handleTestConnection = async () => {
        setIsLoading(true);
        setStatus({ type: null, message: '' });
        try {
            const data = await configApi.validate(config);

            if (data.valid) {
                setStatus({ type: 'success', message: "Connection successful! Models retrieved." });
                if (data.models) {
                    setAvailableModels(data.models);
                }
            } else {
                setStatus({ type: 'error', message: "Connection valid but returned invalid status." });
            }
        } catch (error: any) {
            setStatus({ type: 'error', message: error.message });
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="container mx-auto py-10 max-w-4xl">
            <h1 className="text-2xl font-bold mb-6 flex items-center gap-2">
                <SettingsIcon className="w-6 h-6" />
                Settings
            </h1>
            
            <div className="flex gap-6">
                <div className="w-48 shrink-0">
                    <nav className="flex flex-col space-y-1">
                        <button
                            onClick={() => setActiveTab('llm')}
                            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                                activeTab === 'llm' 
                                    ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100' 
                                    : 'text-muted-foreground hover:bg-slate-50 dark:hover:bg-slate-800/50'
                            }`}
                        >
                            <Bot className="w-4 h-4" />
                            LLM
                        </button>
                        <button
                            onClick={() => setActiveTab('schedule')}
                            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                                activeTab === 'schedule' 
                                    ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100' 
                                    : 'text-muted-foreground hover:bg-slate-50 dark:hover:bg-slate-800/50'
                            }`}
                        >
                            <Clock className="w-4 h-4" />
                            Schedule
                        </button>
                        <button
                            onClick={() => setActiveTab('language')}
                            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                                activeTab === 'language' 
                                    ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100' 
                                    : 'text-muted-foreground hover:bg-slate-50 dark:hover:bg-slate-800/50'
                            }`}
                        >
                            <Globe className="w-4 h-4" />
                            Language
                        </button>
                    </nav>
                </div>
                
                <div className="flex-1">
                    {activeTab === 'llm' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>LLM Configuration</CardTitle>
                                <CardDescription>
                                    Configure your Language Model Provider settings.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                {status.message && (
                                    <div className={`p-3 rounded-md text-sm ${status.type === 'error' ? 'bg-red-50 text-red-900 border border-red-200' : 'bg-green-50 text-green-900 border border-green-200'}`}>
                                        {status.message}
                                    </div>
                                )}

                                <div className="space-y-2">
                                    <label className="text-sm font-medium leading-none">Base URL</label>
                                    <Input 
                                        placeholder="https://api.openai.com/v1" 
                                        value={config.base_url}
                                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setConfig({...config, base_url: e.target.value})}
                                    />
                                    <p className="text-sm text-muted-foreground">
                                        The API endpoint for your LLM provider.
                                    </p>
                                </div>

                                <div className="space-y-2">
                                    <label className="text-sm font-medium leading-none">API Key</label>
                                    <Input 
                                        type="password"
                                        placeholder="sk-..." 
                                        value={config.api_key}
                                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setConfig({...config, api_key: e.target.value})}
                                    />
                                    <p className="text-sm text-muted-foreground">
                                        Your API key. It will be masked when saved.
                                    </p>
                                </div>

                                <div className="space-y-2">
                                    <label className="text-sm font-medium leading-none">Model</label>
                                    <div className="flex gap-2">
                                        <div className="flex-1">
                                            {availableModels.length > 0 ? (
                                                <Select 
                                                    value={config.model} 
                                                    onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setConfig({...config, model: e.target.value})}
                                                >
                                                    <option value="" disabled>Select a model</option>
                                                    {availableModels.map((model) => (
                                                        <option key={model} value={model}>
                                                            {model}
                                                        </option>
                                                    ))}
                                                </Select>
                                            ) : (
                                                <Input 
                                                    placeholder="gpt-4o" 
                                                    value={config.model}
                                                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setConfig({...config, model: e.target.value})}
                                                />
                                            )}
                                        </div>
                                        <Button variant="outline" onClick={handleTestConnection} disabled={isLoading}>
                                            Refresh Models
                                        </Button>
                                    </div>
                                </div>

                                <div className="flex justify-end gap-4 pt-4">
                                    <Button variant="outline" onClick={handleTestConnection} disabled={isLoading}>
                                        Test Connection
                                    </Button>
                                    <Button onClick={handleSave} disabled={isLoading}>
                                        {isLoading ? "Saving..." : "Save Configuration"}
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {activeTab === 'schedule' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Audit Schedule</CardTitle>
                                <CardDescription>
                                    Configure automatic start and stop times for the audit service.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="flex items-center space-x-2">
                                    <input
                                        type="checkbox"
                                        id="schedule-enabled"
                                        className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                                        checked={schedule.enabled}
                                        onChange={(e) => setSchedule({ ...schedule, enabled: e.target.checked })}
                                    />
                                    <label htmlFor="schedule-enabled" className="text-sm font-medium leading-none">
                                        Enable Scheduled Audit
                                    </label>
                                </div>

                                <div className="space-y-4">
                                    {schedule.periods.map((period, index) => (
                                        <div key={index} className="flex items-center gap-2">
                                            <span className="text-sm text-muted-foreground w-6">#{index + 1}</span>
                                            <TimePicker
                                                label="Start"
                                                value={period.start}
                                                onChange={(value) => {
                                                    const newPeriods = [...schedule.periods];
                                                    newPeriods[index] = { ...period, start: value };
                                                    setSchedule({ ...schedule, periods: newPeriods });
                                                }}
                                                disabled={!schedule.enabled}
                                            />
                                            <span className="text-muted-foreground">-</span>
                                            <TimePicker
                                                label="Stop"
                                                value={period.stop}
                                                onChange={(value) => {
                                                    const newPeriods = [...schedule.periods];
                                                    newPeriods[index] = { ...period, stop: value };
                                                    setSchedule({ ...schedule, periods: newPeriods });
                                                }}
                                                disabled={!schedule.enabled}
                                            />
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                onClick={() => {
                                                    const newPeriods = schedule.periods.filter((_, i) => i !== index);
                                                    setSchedule({ ...schedule, periods: newPeriods });
                                                }}
                                                disabled={!schedule.enabled || schedule.periods.length <= 1}
                                                title="Remove period"
                                            >
                                                ×
                                            </Button>
                                        </div>
                                    ))}
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => {
                                            setSchedule({
                                                ...schedule,
                                                periods: [...schedule.periods, { start: '12:00', stop: '14:00' }]
                                            });
                                        }}
                                        disabled={!schedule.enabled}
                                    >
                                        + Add Time Period
                                    </Button>
                                </div>

                                <div className="flex justify-end pt-4">
                                    <Button onClick={handleSaveSchedule} disabled={isLoading}>
                                        {isLoading ? "Saving..." : "Save Schedule"}
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {activeTab === 'language' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Report Language</CardTitle>
                                <CardDescription>
                                    Configure the language for audit reports and finding descriptions.
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-4">
                                <div className="space-y-2">
                                    <label className="text-sm font-medium leading-none">Language</label>
                                    <select
                                        className="w-full px-3 py-2 border rounded-md bg-background"
                                        value={reportLanguage}
                                        onChange={(e) => setReportLanguage(e.target.value)}
                                    >
                                        <option value="Chinese">Chinese (中文)</option>
                                        <option value="English">English (英文)</option>
                                    </select>
                                </div>
                                <div className="flex justify-end pt-4">
                                    <Button onClick={handleSaveReportLanguage} disabled={isLoading}>
                                        {isLoading ? "Saving..." : "Save Language"}
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </div>
            </div>
        </div>
    );
}
