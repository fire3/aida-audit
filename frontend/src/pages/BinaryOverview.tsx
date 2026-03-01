import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { formatAddress } from '../lib/utils';
import { useTranslation } from 'react-i18next';

export function BinaryOverview() {
  const { t } = useTranslation();
  const { binaryName } = useParams();

  const { data: metadata, isLoading } = useQuery({
    queryKey: ['binaryMetadata', binaryName],
    queryFn: () => binaryApi.getMetadata(binaryName!),
    enabled: !!binaryName,
  });

  if (isLoading) return <div>{t('binary_overview.loading')}</div>;

  const formatSize = (bytes?: number) => {
    if (bytes === undefined) return 'N/A';
    if (bytes < 1024) return bytes + ' B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="p-6 space-y-6">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
         {/* Basic Info */}
         <Card className="col-span-1 md:col-span-2">
            <CardHeader>
                <CardTitle className="text-base">{t('binary_overview.basic_info')}</CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-4 text-sm">
                <div>
                    <span className="text-muted-foreground block">{t('binary_overview.binary_name')}</span>
                    <span className="font-medium break-all">{metadata?.binary_name}</span>
                </div>
                <div>
                    <span className="text-muted-foreground block">{t('binary_overview.arch')}</span>
                    <span className="font-medium">{metadata?.arch || t('binary_overview.unknown')}</span>
                </div>
                 <div>
                    <span className="text-muted-foreground block">{t('binary_overview.format')}</span>
                    <span className="font-medium">{metadata?.format || t('binary_overview.unknown')}</span>
                </div>
                <div>
                    <span className="text-muted-foreground block">{t('binary_overview.size')}</span>
                    <span className="font-medium">{formatSize(metadata?.size)}</span>
                </div>
                 <div>
                    <span className="text-muted-foreground block">{t('binary_overview.image_base')}</span>
                    <span className="font-medium font-mono">{formatAddress(metadata?.image_base) || 'N/A'}</span>
                </div>
                 <div>
                    <span className="text-muted-foreground block">{t('binary_overview.endian')}</span>
                    <span className="font-medium">{metadata?.endian || 'N/A'}</span>
                </div>
                 <div>
                    <span className="text-muted-foreground block">{t('binary_overview.analysis_date')}</span>
                    <span className="font-medium">{metadata?.created_at ? new Date(metadata.created_at).toLocaleString() : 'N/A'}</span>
                </div>
                 <div>
                    <span className="text-muted-foreground block">{t('binary_overview.compiler')}</span>
                    <span className="font-medium">{metadata?.compiler?.compiler_name || 'N/A'}</span>
                </div>
            </CardContent>
         </Card>

          {/* Statistics */}
          <Card>
            <CardHeader>
                <CardTitle className="text-base">{t('binary_overview.stats')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
                <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t('binary_overview.total_functions')}</span>
                    <span className="font-bold bg-secondary px-2 py-1 rounded">{metadata?.counts?.functions ?? 0}</span>
                </div>
                {metadata?.counts?.user_functions !== undefined && (
                    <div className="flex justify-between items-center pl-3 border-l-2">
                        <span className="text-muted-foreground text-xs">{t('binary_overview.user_functions')}</span>
                        <span className="font-medium text-xs">{metadata?.counts?.user_functions}</span>
                    </div>
                )}
                {metadata?.counts?.library_functions !== undefined && (
                     <div className="flex justify-between items-center pl-3 border-l-2">
                        <span className="text-muted-foreground text-xs">{t('binary_overview.library_functions')}</span>
                        <span className="font-medium text-xs">{metadata?.counts?.library_functions}</span>
                    </div>
                )}
                 <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t('binary_overview.segments')}</span>
                    <span className="font-bold bg-secondary px-2 py-1 rounded">{metadata?.counts?.segments ?? 0}</span>
                </div>
                 <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">{t('binary_overview.imports')}</span>
                    <span className="font-bold bg-secondary px-2 py-1 rounded">{metadata?.counts?.imports ?? 0}</span>
                </div>
                 <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Exports</span>
                    <span className="font-bold bg-secondary px-2 py-1 rounded">{metadata?.counts?.exports ?? 0}</span>
                </div>
                 <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Symbols</span>
                    <span className="font-bold bg-secondary px-2 py-1 rounded">{metadata?.counts?.symbols ?? 0}</span>
                </div>
                 <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Strings</span>
                    <span className="font-bold bg-secondary px-2 py-1 rounded">{metadata?.counts?.strings ?? 0}</span>
                </div>
            </CardContent>
         </Card>
      </div>
      
      {/* Hashes & Details */}
       <Card>
            <CardHeader className="pb-2">
                <CardTitle className="text-base">File Hashes & Details</CardTitle>
            </CardHeader>
             <CardContent>
                <div className="space-y-2 text-sm">
                    <div className="grid grid-cols-[80px_1fr] gap-2 items-center">
                         <span className="text-muted-foreground">MD5</span>
                         <code className="bg-muted px-2 py-1 rounded text-xs font-mono break-all">{metadata?.hashes?.md5 || 'N/A'}</code>
                    </div>
                     <div className="grid grid-cols-[80px_1fr] gap-2 items-center">
                         <span className="text-muted-foreground">SHA256</span>
                         <code className="bg-muted px-2 py-1 rounded text-xs font-mono break-all">{metadata?.hashes?.sha256 || 'N/A'}</code>
                    </div>
                     <div className="grid grid-cols-[80px_1fr] gap-2 items-center">
                         <span className="text-muted-foreground">CRC32</span>
                         <code className="bg-muted px-2 py-1 rounded text-xs font-mono break-all">{metadata?.hashes?.crc32 || 'N/A'}</code>
                    </div>
                </div>
            </CardContent>
       </Card>
    </div>
  );
}
