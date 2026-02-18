import { useState, useEffect } from 'react';
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Select } from "../components/ui/select";

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
    const [isLoading, setIsLoading] = useState(false);
    const [availableModels, setAvailableModels] = useState<string[]>([]);
    const [status, setStatus] = useState<{ type: 'success' | 'error' | null, message: string }>({ type: null, message: '' });

    useEffect(() => {
        fetchConfig();
    }, []);

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
        </div>
    );
}
