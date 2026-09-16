import React from 'react';

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  interactive?: boolean;
  className?: string;
}

export const Card: React.FC<CardProps> = ({ children, interactive = true, className = '', ...props }) => {
  return (
    <div
      className={`rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/60 p-5 shadow-xs dark:shadow-none backdrop-blur-sm ${
        interactive ? 'hover-card cursor-pointer' : ''
      } ${className}`}
      {...props}
    >
      {children}
    </div>
  );
};
