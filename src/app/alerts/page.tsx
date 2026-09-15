'use client';

import React, { useState } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import { Modal } from '../../components/ui/Modal';
import { SecurityAlert } from '../../types';
import {
  AlertTriangle,
  ShieldCheck,
  CheckCircle,
  Filter,
  Info,
  Server,
  UserX,
  CheckCircle2,
} from 'lucide-react';

export default function AlertsPage() {
  const { alerts, markAlertReviewed, resolveAlert } = useDemoContext();
  const [statusTab, setStatusTab] = useState<'active' | 'reviewed' | 'resolved'>('active');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);

  const filteredAlerts = alerts.filter((alert) => {
    const matchesStatus = alert.status === statusTab;
    const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
    return matchesStatus && matchesSeverity;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-400" />
            Security Threat Alert Center
          </h1>
          <p className="text-xs text-zinc-400 mt-1">
            Review active security incidents, phishing campaigns, and endpoint policy violations.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="rounded-md border border-zinc-800 bg-zinc-900 px-3 py-1 text-[11px] text-zinc-400">
            {alerts.filter((a) => a.status === 'active').length} Active Alerts
          </span>
        </div>
      </div>

      {/* Tabs & Severity Filters */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Status Tabs */}
        <div className="flex items-center gap-1 rounded-lg border border-zinc-800 bg-zinc-950 p-1">
          {(['active', 'reviewed', 'resolved'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setStatusTab(tab)}
              className={`rounded-md px-3 py-1.5 text-xs font-semibold capitalize transition-colors ${
                statusTab === tab
                  ? 'bg-zinc-800 text-zinc-100 shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {tab} ({alerts.filter((a) => a.status === tab).length})
            </button>
          ))}
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-1 rounded-lg border border-zinc-800 bg-zinc-950 p-1">
          <Filter className="h-3.5 w-3.5 text-zinc-500 ml-1.5" />
          <span className="text-[11px] text-zinc-400 mr-1">Severity:</span>
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`rounded-md px-2 py-1 text-xs capitalize transition-colors ${
                severityFilter === sev
                  ? 'bg-zinc-800 text-zinc-100 font-medium'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Alerts List */}
      <Card className="p-0 overflow-hidden">
        <div className="divide-y divide-zinc-800/60">
          {filteredAlerts.length > 0 ? (
            filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                onClick={() => setSelectedAlert(alert)}
                className="p-4 hover-card cursor-pointer hover:bg-zinc-800/40 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="space-y-1 min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <Badge level={alert.severity}>{alert.severity}</Badge>
                    <span className="text-xs font-semibold text-zinc-400">{alert.category}</span>
                    <span className="text-zinc-600">•</span>
                    <h3 className="text-sm font-bold text-zinc-100 truncate">{alert.title}</h3>
                  </div>
                  <p className="text-xs text-zinc-400 line-clamp-1">{alert.description}</p>
                  <div className="flex items-center gap-3 text-[11px] text-zinc-500 pt-1">
                    <span>Affected: {alert.affectedEmployee}</span>
                    <span>•</span>
                    <span>{alert.timestamp}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 sm:self-center" onClick={(e) => e.stopPropagation()}>
                  {alert.status === 'active' && (
                    <button
                      onClick={() => markAlertReviewed(alert.id)}
                      className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 transition-colors"
                    >
                      Mark Reviewed
                    </button>
                  )}
                  {alert.status !== 'resolved' && (
                    <button
                      onClick={() => resolveAlert(alert.id)}
                      className="rounded-lg border border-emerald-900/50 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-400 hover:bg-emerald-900/60 transition-colors"
                    >
                      Resolve
                    </button>
                  )}
                  {alert.status === 'resolved' && (
                    <span className="flex items-center gap-1 text-xs text-emerald-400 font-medium">
                      <CheckCircle2 className="h-4 w-4" /> Resolved
                    </span>
                  )}
                </div>
              </div>
            ))
          ) : (
            <div className="py-12 text-center text-xs text-zinc-500">
              <ShieldCheck className="h-8 w-8 text-zinc-600 mx-auto mb-2" />
              No alerts found under <strong className="text-zinc-300">{statusTab}</strong> status.
            </div>
          )}
        </div>
      </Card>

      {/* Alert Details Inspection Modal */}
      {selectedAlert && (
        <Modal
          isOpen={!!selectedAlert}
          onClose={() => setSelectedAlert(null)}
          title="Incident Threat Telemetry"
          subtitle={`Alert ID: ${selectedAlert.id} • ${selectedAlert.category}`}
          maxWidth="xl"
        >
          <div className="space-y-4">
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-zinc-400">{selectedAlert.category}</span>
                <Badge level={selectedAlert.severity}>{selectedAlert.severity}</Badge>
              </div>
              <h3 className="text-base font-bold text-zinc-100">{selectedAlert.title}</h3>
              <p className="text-xs text-zinc-300 leading-relaxed">{selectedAlert.description}</p>
            </div>

            {/* AI Mitigation Plan */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 space-y-1.5">
              <div className="text-xs font-semibold text-zinc-200">SentinelAI Automated Mitigation</div>
              <p className="text-xs text-zinc-300 leading-relaxed">{selectedAlert.aiMitigationPlan}</p>
            </div>

            {/* Technical Indicators */}
            {selectedAlert.technicalDetails && (
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 space-y-2 text-xs">
                <span className="text-[10px] text-zinc-500 uppercase font-semibold">Technical Threat Indicators</span>
                {selectedAlert.technicalDetails.sourceIp && (
                  <p className="text-zinc-300 font-mono">Source IP: {selectedAlert.technicalDetails.sourceIp}</p>
                )}
                {selectedAlert.technicalDetails.targetResource && (
                  <p className="text-zinc-300">Target Resource: {selectedAlert.technicalDetails.targetResource}</p>
                )}
                {selectedAlert.technicalDetails.threatIndicators && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    {selectedAlert.technicalDetails.threatIndicators.map((ind, i) => (
                      <span key={i} className="rounded border border-zinc-800 bg-zinc-900 px-2 py-0.5 text-[11px] text-zinc-400">
                        {ind}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-end gap-2 border-t border-zinc-800 pt-4">
              {selectedAlert.status === 'active' && (
                <button
                  onClick={() => {
                    markAlertReviewed(selectedAlert.id);
                    setSelectedAlert(null);
                  }}
                  className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800"
                >
                  Mark as Reviewed
                </button>
              )}
              {selectedAlert.status !== 'resolved' && (
                <button
                  onClick={() => {
                    resolveAlert(selectedAlert.id);
                    setSelectedAlert(null);
                  }}
                  className="rounded-lg border border-emerald-900/50 bg-emerald-950/40 px-4 py-1.5 text-xs font-semibold text-emerald-400 hover:bg-emerald-900/60"
                >
                  Resolve Incident
                </button>
              )}
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
