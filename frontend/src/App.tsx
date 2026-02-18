import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { MainLayout } from './layouts/MainLayout';
import { Dashboard } from './pages/Dashboard';
import { BinaryLayout } from './layouts/BinaryLayout';
import { BinaryOverview } from './pages/BinaryOverview';
import { FunctionsBrowser } from './pages/FunctionsBrowser';
import { StringsBrowser } from './pages/StringsBrowser';
import { ImportsBrowser } from './pages/ImportsBrowser';
import { ExportsBrowser } from './pages/ExportsBrowser';
import { SymbolsBrowser } from './pages/SymbolsBrowser';
import { SegmentsBrowser } from './pages/SegmentsBrowser';
import { ProjectNotes } from './pages/ProjectNotes';
import { AuditDashboard } from './pages/AuditDashboard';
import { Settings } from './pages/Settings';
import { useParams } from 'react-router-dom';

function BinaryNotesWrapper() {
  const { binaryName } = useParams();
  return <ProjectNotes initialBinaryName={binaryName} hideBinaryFilter={true} />;
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 1000 * 60 * 5, // 5 minutes
    },
  },
});

function Placeholder({ title }: { title: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-[50vh] text-muted-foreground">
      <h3 className="text-xl font-semibold mb-2">{title}</h3>
      <p>This view is under construction.</p>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<MainLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="audit" element={<AuditDashboard />} />
            <Route path="notes" element={<ProjectNotes />} />
            <Route path="settings" element={<Settings />} />
            
            <Route path="binary/:binaryName" element={<BinaryLayout />}>
              <Route index element={<Navigate to="overview" replace />} />
              <Route path="overview" element={<BinaryOverview />} />
              <Route path="functions" element={<FunctionsBrowser />} />
              <Route path="strings" element={<StringsBrowser />} />
              <Route path="imports" element={<ImportsBrowser />} />
              <Route path="exports" element={<ExportsBrowser />} />
              <Route path="symbols" element={<SymbolsBrowser />} />
              <Route path="segments" element={<SegmentsBrowser />} />
              <Route path="notes" element={<BinaryNotesWrapper />} />
            </Route>
            
            <Route path="*" element={<Placeholder title="404 Not Found" />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
