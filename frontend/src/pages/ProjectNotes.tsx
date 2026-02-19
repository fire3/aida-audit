import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { notesApi } from '../api/client';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { Search, Plus, Filter, AlertTriangle, FileText, Tag, Trash2 } from 'lucide-react';
import { cn } from '../lib/utils';
import { AddNoteDialog } from '../components/AddNoteDialog';
import { AddVulnerabilityDialog } from '../components/AddVulnerabilityDialog';

interface ProjectNotesProps {
  initialBinaryName?: string;
  hideBinaryFilter?: boolean;
  embedded?: boolean;
}

export function ProjectNotes({ initialBinaryName, hideBinaryFilter = false, embedded = false }: ProjectNotesProps) {
  const [activeTab, setActiveTab] = useState<'notes' | 'vulnerabilities'>('notes');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedBinary, setSelectedBinary] = useState<string | undefined>(initialBinaryName);
  const [isAddNoteOpen, setIsAddNoteOpen] = useState(false);
  const [isAddVulnerabilityOpen, setIsAddVulnerabilityOpen] = useState(false);
  
  const queryClient = useQueryClient();

  // Update selectedBinary if initialBinaryName changes
  useEffect(() => {
    if (initialBinaryName) {
        setSelectedBinary(initialBinaryName);
    }
  }, [initialBinaryName]);

  // Notes Query
  const { data: notes, isLoading: isNotesLoading } = useQuery({
    queryKey: ['notes', searchQuery, selectedBinary],
    queryFn: () => notesApi.getNotes({ query: searchQuery, binary_name: selectedBinary }),
    enabled: activeTab === 'notes',
  });

  // Vulnerabilities Query
  const { data: vulnerabilities, isLoading: isVulnerabilitiesLoading } = useQuery({
    queryKey: ['vulnerabilities', selectedBinary],
    queryFn: () => notesApi.getVulnerabilities({ binary_name: selectedBinary }),
    enabled: activeTab === 'vulnerabilities',
  });

  // Delete Note Mutation
  const deleteNoteMutation = useMutation({
    mutationFn: notesApi.deleteNote,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notes'] });
    },
  });

  const handleDeleteNote = async (id: number) => {
    if (confirm('Are you sure you want to delete this note?')) {
      await deleteNoteMutation.mutateAsync(id);
    }
  };

  const handleAddClick = () => {
    if (activeTab === 'notes') {
      setIsAddNoteOpen(true);
    } else {
      setIsAddVulnerabilityOpen(true);
    }
  };

  return (
    <div className={cn("space-y-6", !embedded && "container py-6")}>
      <div className="flex items-center justify-between">
        <h1 className={cn("font-bold tracking-tight", embedded ? "text-xl" : "text-3xl")}>
            {embedded ? "Notes & Vulnerabilities" : "Project Notes & Vulnerabilities"}
        </h1>
        <div className="flex items-center space-x-2">
            <Button onClick={handleAddClick} size={embedded ? "sm" : "default"}>
                <Plus className="mr-2 h-4 w-4" />
                Add {activeTab === 'notes' ? 'Note' : 'Vulnerability'}
            </Button>
        </div>
      </div>

      <AddNoteDialog 
        isOpen={isAddNoteOpen} 
        onClose={() => setIsAddNoteOpen(false)} 
        initialBinaryName={selectedBinary}
      />

      <AddVulnerabilityDialog 
        isOpen={isAddVulnerabilityOpen} 
        onClose={() => setIsAddVulnerabilityOpen(false)}
        initialBinaryName={selectedBinary}
      />

      {/* Tabs */}
      <div className="flex space-x-1 border-b">
        <button
          onClick={() => setActiveTab('notes')}
          className={cn(
            "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
            activeTab === 'notes' 
              ? "border-primary text-primary" 
              : "border-transparent text-muted-foreground hover:text-foreground"
          )}
        >
          Notes
        </button>
        <button
          onClick={() => setActiveTab('vulnerabilities')}
          className={cn(
            "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
            activeTab === 'vulnerabilities' 
              ? "border-primary text-primary" 
              : "border-transparent text-muted-foreground hover:text-foreground"
          )}
        >
          Vulnerabilities
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center space-x-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={activeTab === 'notes' ? "Search notes..." : "Search vulnerabilities..."}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8"
          />
        </div>
        {!hideBinaryFilter && (
            <div className="relative">
                <Filter className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input 
                    placeholder="Filter by binary..." 
                    value={selectedBinary || ''}
                    onChange={(e) => setSelectedBinary(e.target.value || undefined)}
                    className="pl-8 w-[200px]"
                />
            </div>
        )}
      </div>

      {/* Content */}
      <div className="grid gap-4">
        {activeTab === 'notes' ? (
            isNotesLoading ? (
                <div>Loading notes...</div>
            ) : notes?.length === 0 ? (
                <div className="text-center py-10 text-muted-foreground">No notes found.</div>
            ) : (
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                    {notes?.map((note) => (
                        <Card key={note.note_id} className="flex flex-col">
                            <CardHeader className="pb-2">
                                <div className="flex justify-between items-start">
                                    <div className="space-y-1">
                                        <CardTitle className="text-base font-semibold flex items-center gap-2">
                                            <FileText className="h-4 w-4 text-blue-500" />
                                            {note.note_type}
                                        </CardTitle>
                                        <CardDescription className="text-xs">
                                            {note.binary_name} 
                                            {note.function_name && ` • ${note.function_name}`}
                                            {note.address && ` • ${note.address}`}
                                        </CardDescription>
                                    </div>
                                    <div className="flex space-x-1">
                                        <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => handleDeleteNote(note.note_id)}>
                                            <Trash2 className="h-3 w-3 text-destructive" />
                                        </Button>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent className="flex-1 text-sm">
                                <p className="whitespace-pre-wrap">{note.content}</p>
                                {note.tags && note.tags.length > 0 && (
                                    <div className="flex flex-wrap gap-1 mt-3">
                                        {note.tags.map(tag => (
                                            <span key={tag} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-secondary text-secondary-foreground">
                                                <Tag className="mr-1 h-3 w-3" />
                                                {tag}
                                            </span>
                                        ))}
                                    </div>
                                )}
                                <div className="mt-4 text-xs text-muted-foreground">
                                    {new Date(note.created_at).toLocaleString()}
                                </div>
                            </CardContent>
                        </Card>
                    ))}
                </div>
            )
        ) : (
            isVulnerabilitiesLoading ? (
                <div>Loading vulnerabilities...</div>
            ) : vulnerabilities?.length === 0 ? (
                <div className="text-center py-10 text-muted-foreground">No vulnerabilities found.</div>
            ) : (
                <div className="grid gap-4">
                    {vulnerabilities?.map((vulnerability) => (
                        <Card key={vulnerability.finding_id}>
                            <CardHeader>
                                <div className="flex justify-between items-start">
                                    <div>
                                        <CardTitle className="text-lg flex items-center gap-2">
                                            <AlertTriangle className={cn(
                                                "h-5 w-5", 
                                                vulnerability.severity === 'high' || vulnerability.severity === 'critical' ? "text-red-500" :
                                                vulnerability.severity === 'medium' ? "text-yellow-500" : "text-blue-500"
                                            )} />
                                            {vulnerability.category}
                                        </CardTitle>
                                        <CardDescription>
                                            {vulnerability.binary_name} 
                                            {vulnerability.function_name && ` • ${vulnerability.function_name}`}
                                            {vulnerability.address && ` • ${vulnerability.address}`}
                                        </CardDescription>
                                    </div>
                                    <div className="text-right">
                                        <div className={cn(
                                            "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium uppercase",
                                            vulnerability.severity === 'high' || vulnerability.severity === 'critical' ? "bg-red-100 text-red-800" :
                                            vulnerability.severity === 'medium' ? "bg-yellow-100 text-yellow-800" : "bg-blue-100 text-blue-800"
                                        )}>
                                            {vulnerability.severity}
                                        </div>
                                        {vulnerability.cvss && (
                                            <div className="text-xs text-muted-foreground mt-1">CVSS: {vulnerability.cvss}</div>
                                        )}
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm whitespace-pre-wrap mb-4">{vulnerability.description}</p>
                                {vulnerability.evidence && (
                                    <div className="bg-muted p-3 rounded-md font-mono text-xs overflow-x-auto">
                                        {vulnerability.evidence}
                                    </div>
                                )}
                            </CardContent>
                        </Card>
                    ))}
                </div>
            )
        )}
      </div>
    </div>
  );
}
