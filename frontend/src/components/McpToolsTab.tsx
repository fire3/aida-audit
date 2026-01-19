import { useQuery } from '@tanstack/react-query';
import { projectApi } from '../api/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Code } from 'lucide-react';

export function McpToolsTab() {
  const { data: mcpTools, isLoading: isMcpToolsLoading } = useQuery({
    queryKey: ['mcpTools'],
    queryFn: projectApi.getMcpTools,
  });

  return (
    <div>
      <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
        <Code className="h-5 w-5" />
        Available MCP Tools
      </h2>
      {isMcpToolsLoading ? (
        <div className="py-8 text-center text-muted-foreground">Loading available tools...</div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {mcpTools?.map((tool: any) => (
            <Card key={tool.name} className="flex flex-col">
              <CardHeader className="pb-2">
                <CardTitle className="font-mono text-base text-primary">{tool.name}</CardTitle>
                <CardDescription className="text-sm mt-1 whitespace-pre-wrap">{tool.description}</CardDescription>
              </CardHeader>
              <CardContent className="flex-1">
                <div className="text-xs font-semibold mb-2 text-muted-foreground uppercase tracking-wider">Parameters</div>
                <div className="bg-muted p-3 rounded-md text-xs font-mono overflow-x-auto">
                  <ul className="list-disc list-inside space-y-1">
                    {Object.entries(tool.inputSchema.properties).map(([param, details]: [string, any]) => (
                      <li key={param}>
                        <span className="font-bold text-foreground">{param}</span>
                        <span className="text-muted-foreground ml-1">({details.type})</span>
                        {tool.inputSchema.required?.includes(param) && (
                          <span className="ml-2 text-red-500 text-[10px] uppercase font-bold">Required</span>
                        )}
                      </li>
                    ))}
                    {Object.keys(tool.inputSchema.properties).length === 0 && (
                      <li className="text-muted-foreground italic">No parameters required</li>
                    )}
                  </ul>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
