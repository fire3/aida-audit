import { Outlet, NavLink, useParams } from 'react-router-dom';
import { cn } from '../lib/utils';
import { FileCode, Braces, AlignLeft, ArrowRightLeft, Database, Box } from 'lucide-react';
import { useTranslation } from 'react-i18next';

export function BinaryLayout() {
  const { t } = useTranslation();
  const { binaryName } = useParams();

  const navItems = [
    { to: 'overview', icon: FileCode, label: t('nav.overview') },
    { to: 'functions', icon: Braces, label: t('nav.functions') },
    { to: 'strings', icon: AlignLeft, label: t('nav.strings') },
    { to: 'imports', icon: ArrowRightLeft, label: t('nav.imports') },
    { to: 'exports', icon: ArrowRightLeft, label: t('nav.exports') },
    { to: 'symbols', icon: Database, label: t('nav.symbols') },
    { to: 'segments', icon: Box, label: t('nav.segments') },
  ];

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)] lg:flex-row">
      <aside className="w-full lg:w-64 flex-shrink-0 border-r bg-muted/10">
        <div className="p-4 border-b">
            <h2 className="text-lg font-semibold tracking-tight truncate" title={binaryName}>
                {binaryName}
            </h2>
            <p className="text-sm text-muted-foreground">{t('nav.binary_analysis')}</p>
        </div>
        <nav className="flex space-x-2 lg:flex-col lg:space-x-0 lg:space-y-1 overflow-x-auto lg:overflow-visible p-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  "justify-start flex items-center whitespace-nowrap rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground"
                )
              }
            >
              <item.icon className="mr-2 h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="flex-1 overflow-hidden">
        <Outlet />
      </main>
    </div>
  );
}
