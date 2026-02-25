import { CheckCircle2, Circle, AlertCircle, AlertTriangle, Clock } from 'lucide-react';

export function Badge({ children, variant }: { children: React.ReactNode, variant: string }) {
    const colors = {
        default: "bg-green-100 text-green-800 border border-green-200",
        secondary: "bg-blue-100 text-blue-800 border border-blue-200",
        outline: "bg-gray-100 text-gray-800 border border-gray-200",
        destructive: "bg-red-100 text-red-800 border border-red-200",
        warning: "bg-yellow-100 text-yellow-800 border border-yellow-200",
        info: "bg-sky-100 text-sky-800 border border-sky-200",
        purple: "bg-purple-100 text-purple-800 border border-purple-200",
        orange: "bg-orange-100 text-orange-800 border border-orange-200"
    };
    const style = colors[variant as keyof typeof colors] || colors.outline;
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide ${style}`}>
            {children}
        </span>
    )
}

export function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'completed': return <CheckCircle2 className="w-4 h-4 text-green-500" />;
    case 'in_progress': return <Clock className="w-4 h-4 text-blue-500 animate-pulse" />;
    case 'failed': return <AlertCircle className="w-4 h-4 text-red-500" />;
    default: return <Circle className="w-4 h-4 text-gray-300" />;
  }
}

export function VerificationStatusBadge({ status }: { status: string | undefined }) {
  if (!status) status = 'unverified';
  const colors: Record<string, string> = {
    unverified: "bg-slate-100 text-slate-500 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
    confirmed: "bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-900",
    false_positive: "bg-green-100 text-green-700 border-green-200 dark:bg-green-900/30 dark:text-green-400 dark:border-green-900",
  };
  const style = colors[status] || colors.unverified;
  const icon = status === 'confirmed' ? <AlertTriangle className="w-3 h-3 mr-1" /> : 
               status === 'false_positive' ? <CheckCircle2 className="w-3 h-3 mr-1" /> :
               <Circle className="w-3 h-3 mr-1" />;
              
  return (
      <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide border flex items-center ${style}`}>
          {icon}
          {status.replace('_', ' ')}
      </span>
  )
}
