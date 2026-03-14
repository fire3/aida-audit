import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Activity } from 'lucide-react';

export function AboutTab() {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>About AIDA MCP Service</CardTitle>
          <CardDescription>
            This service exposes static analysis data from your IDA Pro projects through the Model Context Protocol (MCP) compatible interface.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p>
            The service allows LLM agents to inspect binary analysis results, including functions, strings, cross-references, and disassembly.
          </p>
          
          <div className="bg-muted p-4 rounded-md">
            <h3 className="font-semibold mb-2 flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Getting Started
            </h3>
            <div className="space-y-4 text-sm">
              <div>
                <div className="font-medium mb-1">1. Export Analysis Data</div>
                <p className="text-muted-foreground">
                  Use the <code>ida_exporter.py</code> script within IDA Pro to export your binary analysis database.
                </p>
              </div>
              <div>
                <div className="font-medium mb-1">2. Configure Server</div>
                <p className="text-muted-foreground">
                  Set the <code>IDA_MCP_PROJECT</code> environment variable to your exported project directory.
                </p>
              </div>
              <div>
                <div className="font-medium mb-1">3. Connect MCP Client</div>
                <p className="text-muted-foreground mb-2">
                  Configure OpenCode to connect to this server.
                  Below is an example <code>opencode.json</code> configuration:
                </p>
                <pre className="bg-background p-2 rounded border text-xs overflow-auto font-mono">
{`{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "aida-audit": {
      "type": "remote",
      "url": "http://localhost:8765/mcp",
      "enabled": true
    }
  }
}`}
                </pre>
                <p className="text-xs text-muted-foreground mt-2">
                  * Note: Ensure the <code>aida-audit</code> package is installed or in your PYTHONPATH.
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
