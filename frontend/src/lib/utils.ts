import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatAddress(addr: string | number | undefined | null): string {
  if (addr === undefined || addr === null || addr === '') return '';
  
  if (typeof addr === 'number') {
    return `0x${BigInt(addr).toString(16).toUpperCase()}`;
  }

  if (addr.startsWith('0x')) return addr;
  try {
    // Check if it's a valid decimal number string
    if (/^\d+$/.test(addr)) {
       return `0x${BigInt(addr).toString(16).toUpperCase()}`;
    }
  } catch (e) {
    // ignore
  }
  return addr;
}
