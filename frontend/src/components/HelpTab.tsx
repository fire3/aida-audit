import { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Card, CardContent } from './ui/card';

export function HelpTab() {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/help.md')
      .then(res => {
        if (!res.ok) {
          throw new Error('Failed to load help document');
        }
        return res.text();
      })
      .then(text => {
        setContent(text);
        setLoading(false);
      })
      .catch(err => {
        console.error('Error loading help:', err);
        setError('Failed to load help content. Please try again later.');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div className="p-4 text-center text-muted-foreground">Loading help documentation...</div>;
  }

  if (error) {
    return <div className="p-4 text-center text-red-500">{error}</div>;
  }

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="prose prose-sm dark:prose-invert max-w-none">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>
            {content}
          </ReactMarkdown>
        </div>
      </CardContent>
    </Card>
  );
}
