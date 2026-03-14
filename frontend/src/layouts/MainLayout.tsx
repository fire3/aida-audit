import { Link, Outlet } from 'react-router-dom';
import { Layers, Settings, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { buttonVariants } from '../components/ui/button';
import { cn } from '../lib/utils';

export function MainLayout() {
  const { t } = useTranslation();
  return (
    <div className="min-h-screen bg-background font-sans antialiased flex flex-col">
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center">
          <div className="mr-4 flex">
            <Link to="/" className="mr-6 flex items-center space-x-2">
              <Layers className="h-6 w-6" />
              <span className="hidden font-bold sm:inline-block">
                AIDA 
              </span>
            </Link>
            <nav className="flex items-center space-x-6 text-sm font-medium">
              <Link 
                to="/audit"
                className={cn(
                  buttonVariants({ variant: "default", size: "sm" }),
                  "gap-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white shadow-sm hover:shadow-md transition-all duration-300 hover:scale-[1.02]"
                )}
              >
                <ShieldCheck className="h-4 w-4" />
                {t('nav.audit')}
              </Link>
            </nav>
          </div>
          <div className="flex flex-1 items-center justify-between space-x-2 md:justify-end">
             <Link to="/settings" className="text-foreground/60 hover:text-foreground/80" title={t('nav.settings')}>
                <Settings className="h-5 w-5" />
             </Link>
          </div>
        </div>
      </header>
      <main className="flex-1">
        <Outlet />
      </main>
    </div>
  );
}
