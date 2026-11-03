import type { CSSProperties } from 'react';

type IconName = 'devices' | 'search' | 'refresh' | 'arrow' | 'info' | 'close' | 'server';

const paths: Record<IconName, string> = {
  devices: 'M3 4h18v12H3zM8 21h8M12 16v5',
  search: 'M21 21l-5-5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
  refresh: 'M20 7v5h-5M4 17v-5h5M5.6 7a7 7 0 0 1 11.5-2L20 8M4 16l2.9 3a7 7 0 0 0 11.5-2',
  arrow: 'M7 17 17 7M7 7h10v10',
  info: 'M12 11v6M12 7v.1M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
  close: 'm6 6 12 12M6 18 18 6',
  server: 'M4 3h16v7H4zM4 14h16v7H4zM8 6.5h.01M8 17.5h.01',
};

export function Icon({ name, className, style }: { name: IconName; className?: string; style?: CSSProperties }) {
  return (
    <svg className={className} style={style} width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={paths[name]} />
    </svg>
  );
}

export function FleetIllustration() {
  return (
    <svg className="fleet-illustration" viewBox="0 0 240 128" fill="none" aria-hidden="true">
      <path d="M120 61v27M120 88H49v15M120 88h71v15" stroke="#B8C8EA" strokeWidth="2" strokeDasharray="4 5" />
      <rect x="86" y="13" width="68" height="48" rx="8" fill="#EAF0FF" stroke="#89A3E0" strokeWidth="1.5" />
      <path d="M99 26h42M99 35h28M99 44h18" stroke="#6888D1" strokeWidth="2" strokeLinecap="round" />
      <circle cx="141" cy="48" r="3" fill="#315CE8" />
      <rect x="28" y="102" width="42" height="26" rx="4" fill="#F4F7FD" stroke="#B8C8EA" strokeWidth="1.5" />
      <rect x="99" y="102" width="42" height="26" rx="4" fill="#F4F7FD" stroke="#B8C8EA" strokeWidth="1.5" />
      <rect x="170" y="102" width="42" height="26" rx="4" fill="#F4F7FD" stroke="#B8C8EA" strokeWidth="1.5" />
    </svg>
  );
}
