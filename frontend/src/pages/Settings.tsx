import { useState, useEffect } from 'react';
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Select } from "../components/ui/select";
import { scheduleApi, type ScheduleConfig } from '../api/client';

const TIME_PRESETS = [
    { label: '9:00 - 18:00', start: '09:00', stop: '18:00' },
    { label: '8:00 - 20:00', start: '08:00', stop: '20:00' },
    { label: '6:00 - 22:00', start: '06:00', stop: '22:00' },
    { label: '22:00 - 8:00', start: '22:00', stop: '08:00' },
    { label: '24 hours', start: '00:00', stop: '23:59' },
];

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

interface ConfigData {
    base_url: string;
    api_key: string;
    model: string;
}

export function Settings() {
    const [config, setConfig] = useState<ConfigData>({
        base_url: '',
        api_key: '',
        model: ''
    });
    const [schedule, setSchedule] = useState<ScheduleConfig>({
        enabled: false,
        start_time: '09:00',
        stop_time: '18:00'
    });
    const [isLoading, setIsLoading] = useState(false);
    const [availableModels, setAvailableModels] = useState<string[]>([]);
    const [status, setStatus] = useState<{ type: 'success' | 'error' | null, message: string }>({ type: null, message: '' });

    useEffect(() => {
        fetchConfig();
        fetchSchedule();
    }, []);

    const fetchSchedule = async () => {
        try {
            const data = await scheduleApi.get();
            setSchedule(data);
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


    const fetchConfig = async () => {
        try {
            const res = await fetch('/api/v1/config');
            if (!res.ok) throw new Error('Failed to fetch config');
            const data = await res.json();
            setConfig(data);
            if (data.base_url) {
                // If we have a base url, try to list models
                fetchModels(data.base_url, data.api_key || '');
            }
        } catch (error) {
            console.error(error);
            setStatus({ type: 'error', message: "Failed to load configuration" });
        }
    };

    const fetchModels = async (baseUrl: string, apiKey: string) => {
        try {
            // Use validate endpoint to fetch models, using current or empty model for validation
            const res = await fetch('/api/v1/config/validate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    base_url: baseUrl, 
                    api_key: apiKey, 
                    model: config.model || 'gpt-4o' 
                })
            });
            if (!res.ok) throw new Error('Failed to fetch models');
            const data = await res.json();
            if (data.models) {
                setAvailableModels(data.models);
                return data.models;
            }
        } catch (error) {
            console.error(error);
        }
        return [];
    };

    const handleSave = async () => {
        setIsLoading(true);
        setStatus({ type: null, message: '' });
        try {
            const res = await fetch('/api/v1/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Failed to save config');
            }
            
            setStatus({ type: 'success', message: "Configuration saved successfully" });
            
            // Refresh to get masked key back and ensure UI is in sync
            fetchConfig();
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
            const res = await fetch('/api/v1/config/validate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Connection failed');
            }
            
            const data = await res.json();
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
        <div className="container mx-auto py-10 max-w-2xl">
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
                        <label className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">Base URL</label>
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
                        <label className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">API Key</label>
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
                        <label className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">Model</label>
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

            <Card className="mt-8">
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
                        <label htmlFor="schedule-enabled" className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                            Enable Scheduled Audit
                        </label>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <TimePicker
                            label="Start Time"
                            value={schedule.start_time}
                            onChange={(value) => setSchedule({ ...schedule, start_time: value })}
                            disabled={!schedule.enabled}
                        />
                        <TimePicker
                            label="Stop Time"
                            value={schedule.stop_time}
                            onChange={(value) => setSchedule({ ...schedule, stop_time: value })}
                            disabled={!schedule.enabled}
                        />
                    </div>

                    <div className="space-y-2">
                        <label className="text-sm font-medium leading-none">Quick Presets</label>
                        <div className="flex flex-wrap gap-2">
                            {TIME_PRESETS.map((preset) => (
                                <Button
                                    key={preset.label}
                                    variant={schedule.start_time === preset.start && schedule.stop_time === preset.stop ? 'default' : 'outline'}
                                    size="sm"
                                    onClick={() => setSchedule({ ...schedule, start_time: preset.start, stop_time: preset.stop })}
                                    disabled={!schedule.enabled}
                                >
                                    {preset.label}
                                </Button>
                            ))}
                        </div>
                    </div>

                    <div className="flex justify-end pt-4">
                        <Button onClick={handleSaveSchedule} disabled={isLoading}>
                            {isLoading ? "Saving..." : "Save Schedule"}
                        </Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
