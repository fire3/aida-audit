import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import { Button } from '../components/ui/button';
import { Textarea } from '../components/ui/textarea';
import { Play, Loader2 } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

export function SimulationBrowser() {
  const { binaryName } = useParams<{ binaryName: string }>();
  const [script, setScript] = useState<string>('# Write your Flare-Emu DSL script here\n\n');
  const [result, setResult] = useState<any>(null);

  const executeMutation = useMutation({
    mutationFn: (scriptContent: string) => binaryApi.executeDSL(binaryName!, scriptContent),
    onSuccess: (data) => {
      setResult(data);
    },
    onError: (error) => {
      setResult({ error: String(error) });
    }
  });

  const handleExecute = () => {
    executeMutation.mutate(script);
  };

  return (
    <div className="h-full flex flex-col bg-background">
      {/* Header */}
      <div className="flex-none p-4 border-b border-border bg-card/50 flex justify-between items-center">
        <h2 className="text-lg font-semibold">DSL Simulation</h2>
        <Button 
          onClick={handleExecute} 
          disabled={executeMutation.isPending}
        >
          {executeMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}
          Execute
        </Button>
      </div>

      {/* Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Editor (Left) */}
        <div className="w-1/2 flex flex-col border-r border-border">
          <div className="p-2 border-b bg-muted/20 text-xs font-medium text-muted-foreground uppercase tracking-wider">DSL Script</div>
          <div className="flex-1 p-0">
             <Textarea 
                value={script} 
                onChange={(e) => setScript(e.target.value)}
                className="w-full h-full font-mono text-sm resize-none p-4 border-0 focus-visible:ring-0 rounded-none"
                spellCheck={false}
                placeholder="Enter DSL commands..."
             />
          </div>
        </div>

        {/* Results (Right) */}
        <div className="w-1/2 flex flex-col overflow-hidden">
          <div className="p-2 border-b bg-muted/20 text-xs font-medium text-muted-foreground uppercase tracking-wider">Execution Result</div>
          <div className="flex-1 overflow-auto bg-[#1e1e1e]">
             {result ? (
                <SyntaxHighlighter
                  language="json"
                  style={vscDarkPlus}
                  customStyle={{ margin: 0, minHeight: '100%', borderRadius: 0, fontSize: '13px' }}
                  wrapLines={true}
                >
                  {JSON.stringify(result, null, 2)}
                </SyntaxHighlighter>
             ) : (
               <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
                 Run a script to see results here
               </div>
             )}
          </div>
        </div>
      </div>
    </div>
  );
}
