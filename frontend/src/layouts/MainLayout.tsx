import { Link, Outlet } from 'react-router-dom';
import { Layers } from 'lucide-react';

export function MainLayout() {
  return (
    <div className="min-h-screen bg-background font-sans antialiased flex flex-col">
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center">
          <div className="mr-4 flex">
            <Link to="/" className="mr-6 flex items-center space-x-2">
              <Layers className="h-6 w-6" />
              <span className="hidden font-bold sm:inline-block">
                AIDA MCP
              </span>
            </Link>
            <nav className="flex items-center space-x-6 text-sm font-medium">
              <Link
                to="/audit"
                className="transition-colors hover:text-foreground/80 text-foreground/60"
              >
                Audit
              </Link>
              <Link
                to="/notes"
                className="transition-colors hover:text-foreground/80 text-foreground/60"
              >
                Notes & Findings
              </Link>
            </nav>
          </div>
          <div className="flex flex-1 items-center justify-between space-x-2 md:justify-end">
             {/* Search or User Menu could go here */}
          </div>
        </div>
      </header>
      <main className="flex-1">
        <Outlet />
      </main>
    </div>
  );
}
