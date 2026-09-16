'use client';

import React, { useState } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import { Modal } from '../../components/ui/Modal';
import { ActivityEvent } from '../../types';
import {
  Activity,
  Search,
  Globe,
  Mail,
  FileSearch,
  Key,
  Sliders,
} from 'lucide-react';

export default function ActivityPage() {
  const { activities } = useDemoContext();
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedActivity, setSelectedActivity] = useState<ActivityEvent | null>(null);

  const filteredActivities = activities.filter((act) => {
    const matchesSearch =
      act.employeeName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      act.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      act.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = typeFilter === 'all' || act.eventType === typeFilter;
    const matchesSeverity = severityFilter === 'all' || act.severity === severityFilter;
    return matchesSearch && matchesType && matchesSeverity;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-200 dark:border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2 tracking-tight">
            <Activity className="h-5 w-5 text-zinc-600 dark:text-zinc-400" />
            Employee Security Audit Trail
          </h1>
          <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-1">
            Chronological audit log of employee actions, automated checks, and policy modifications.
          </p>
        </div>
        <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-900 px-3 py-1 text-[11px] font-medium text-zinc-600 dark:text-zinc-400">
          Demo Log Telemetry
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-400 dark:text-zinc-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter by employee name, action title, or keywords..."
            className="w-full rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/80 pl-9 pr-4 py-2 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:border-zinc-400 dark:focus:border-zinc-700 focus:outline-hidden"
          />
        </div>

        {/* Type & Severity Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-950 p-1">
            <span className="text-[11px] text-zinc-500 dark:text-zinc-400 ml-1.5 mr-1">Category:</span>
            {[
              { id: 'all', label: 'All' },
              { id: 'email_scan', label: 'Email' },
              { id: 'url_check', label: 'URL' },
              { id: 'document_analysis', label: 'Document' },
              { id: 'auth_event', label: 'Auth' },
            ].map((cat) => (
              <button
                key={cat.id}
                onClick={() => setTypeFilter(cat.id)}
                className={`rounded-md px-2 py-1 text-xs transition-colors cursor-pointer ${
                  typeFilter === cat.id
                    ? 'bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 font-semibold shadow-xs'
                    : 'text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200'
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-950 p-1">
            <span className="text-[11px] text-zinc-500 dark:text-zinc-400 ml-1.5 mr-1">Severity:</span>
            {['all', 'critical', 'warning', 'safe'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`rounded-md px-2 py-1 text-xs capitalize transition-colors cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 font-semibold shadow-xs'
                    : 'text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Activity Timeline List */}
      <Card className="p-0 overflow-hidden">
        <div className="divide-y divide-zinc-200 dark:divide-zinc-800/60">
          {filteredActivities.length > 0 ? (
            filteredActivities.map((act) => (
              <div
                key={act.id}
                onClick={() => setSelectedActivity(act)}
                className="flex items-center justify-between p-4 hover-card cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/40 transition-colors gap-4"
              >
                <div className="flex items-center gap-3.5 min-w-0">
                  <div className="h-9 w-9 rounded-full bg-zinc-100 dark:bg-zinc-800 border border-zinc-300 dark:border-zinc-700 flex items-center justify-center text-xs font-bold text-zinc-700 dark:text-zinc-300 shrink-0">
                    {act.employeeName.charAt(0)}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-xs text-zinc-900 dark:text-zinc-200">{act.employeeName}</span>
                      <span className="text-zinc-300 dark:text-zinc-600">•</span>
                      <span className="text-xs text-zinc-600 dark:text-zinc-400 font-medium">{act.title}</span>
                    </div>
                    <p className="text-[11px] text-zinc-500 truncate mt-0.5">{act.description}</p>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <Badge level={act.severity}>{act.severity}</Badge>
                  <span className="text-[10px] text-zinc-500 whitespace-nowrap">{act.timestamp}</span>
                </div>
              </div>
            ))
          ) : (
            <div className="py-12 text-center text-xs text-zinc-500">
              No security events match the selected criteria.
            </div>
          )}
        </div>
      </Card>

      {/* Activity Telemetry Inspection Modal */}
      {selectedActivity && (
        <Modal
          isOpen={!!selectedActivity}
          onClose={() => setSelectedActivity(null)}
          title="Activity Telemetry Record"
          subtitle={`Event ID: ${selectedActivity.id} • ${selectedActivity.timestamp}`}
        >
          <div className="space-y-4">
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-zinc-500 dark:text-zinc-400">Event Title</span>
                <Badge level={selectedActivity.severity}>{selectedActivity.severity}</Badge>
              </div>
              <p className="text-sm font-bold text-zinc-900 dark:text-zinc-100">{selectedActivity.title}</p>
              <p className="text-xs text-zinc-700 dark:text-zinc-300">{selectedActivity.description}</p>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3">
                <span className="text-[10px] text-zinc-500 block">Employee & Role</span>
                <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">{selectedActivity.employeeName}</p>
                <p className="text-[10px] text-zinc-500 dark:text-zinc-400">{selectedActivity.role}</p>
              </div>
              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3">
                <span className="text-[10px] text-zinc-500 block">IP Address</span>
                <p className="font-semibold font-mono text-zinc-900 dark:text-zinc-200 mt-0.5">{selectedActivity.ipAddress}</p>
              </div>
              <div className="col-span-2 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3">
                <span className="text-[10px] text-zinc-500 block">Endpoint Device</span>
                <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">{selectedActivity.device}</p>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-zinc-200 dark:border-zinc-800">
              <button
                onClick={() => setSelectedActivity(null)}
                className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-900 px-4 py-1.5 text-xs text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-800 cursor-pointer"
              >
                Close Record
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
