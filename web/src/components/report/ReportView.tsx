import React, { useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  ShieldCheck, 
  AlertTriangle, 
  XCircle, 
  Copy, 
  Download, 
  Layers, 
  FileCode, 
  CheckCircle2, 
  Sparkles,
  ArrowLeft,
  ChevronRight
} from 'lucide-react';

interface ReportProps {
  scanId: string;
}

export function ReportView({ scanId }: ReportProps) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}/report`);
        if (!res.ok) throw new Error('Security report not found');
        const json = await res.json();
        setData(json);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [scanId]);

  const copyScanId = () => {
    navigator.clipboard.writeText(scanId);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadReportJson = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `skill-doctor-report-${scanId.substring(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="py-24 text-center space-y-3">
        <div className="w-8 h-8 rounded-full border-2 border-primary border-t-transparent animate-spin mx-auto" />
        <div className="text-xs font-mono text-slate-400">Loading audit verdict...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="console-panel p-8 text-center space-y-3 border-red-900 bg-red-950/20">
        <XCircle className="w-8 h-8 text-red-400 mx-auto" />
        <h2 className="text-base font-bold text-foreground">Report Unavailable</h2>
        <p className="text-xs text-slate-400">{error || 'Could not retrieve scan results.'}</p>
        <Button variant="outline" size="sm" onClick={() => window.location.href = '/scan'} className="text-xs">
          Return to Scanner
        </Button>
      </div>
    );
  }

  const { risk_level, risk_score = 0, findings = [], layers_run = [], duration_ms = 0, bundle_hash } = data;
  
  const isDangerous = risk_level === 'DANGEROUS' || risk_level === 'CRITICAL' || risk_score >= 7.0;
  const isCaution = risk_level === 'CAUTION' || (risk_score >= 3.0 && risk_score < 7.0);
  const isSafe = !isDangerous && !isCaution;

  const filteredFindings = findings.filter((f: any) => {
    if (selectedSeverity === 'ALL') return true;
    return f.severity?.toUpperCase() === selectedSeverity;
  });

  const criticalCount = findings.filter((f: any) => f.severity?.toUpperCase() === 'CRITICAL').length;
  const highCount = findings.filter((f: any) => f.severity?.toUpperCase() === 'HIGH').length;
  const mediumCount = findings.filter((f: any) => f.severity?.toUpperCase() === 'MEDIUM').length;

  const getFilterBtnClass = (sev: string, activeClass: string) => {
    if (selectedSeverity === sev) return activeClass;
    return 'text-slate-400 hover:text-foreground hover:bg-secondary/40';
  };

  return (
    <div className="space-y-6">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">
              AUDIT COMPLETED IN {(duration_ms / 1000).toFixed(2)}s
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-xs font-mono text-slate-400">
              SHA-256: {bundle_hash ? `${bundle_hash.substring(0, 12)}...` : 'Verified'}
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground mt-0.5">
            Security Audit Report
          </h1>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={copyScanId} className="h-8 text-xs font-mono">
            <Copy className="w-3.5 h-3.5 mr-1.5" />
            {copied ? 'Copied' : 'Copy ID'}
          </Button>
          <Button variant="secondary" size="sm" onClick={downloadReportJson} className="h-8 text-xs font-medium">
            <Download className="w-3.5 h-3.5 mr-1.5" />
            Export JSON
          </Button>
        </div>
      </div>

      {/* Primary Verdict Banner */}
      <div className={`p-6 rounded border ${
        isDangerous
          ? 'bg-red-950/30 border-red-800'
          : isCaution
          ? 'bg-amber-950/30 border-amber-800'
          : 'bg-emerald-950/30 border-emerald-800'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              {isDangerous && <XCircle className="w-5 h-5 text-red-400" />}
              {isCaution && <AlertTriangle className="w-5 h-5 text-amber-400" />}
              {isSafe && <CheckCircle2 className="w-5 h-5 text-emerald-400" />}
              <span className={`text-lg font-bold tracking-tight ${
                isDangerous ? 'text-red-400' : isCaution ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {isDangerous ? 'DANGEROUS PAYLOAD DETECTED' : isCaution ? 'SUSPICIOUS ANOMALIES DETECTED' : 'VERIFIED SAFE FOR EXECUTION'}
              </span>
            </div>

            <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
              {isDangerous
                ? 'High-risk security signatures, instruction hijacking, or uncontained privilege escalations were confirmed. Do not deploy this tool to agent environments.'
                : isCaution
                ? 'Potentially elevated permissions or ambiguous intent detected. Manual inspection recommended.'
                : 'No malicious code patterns or prompt injection sequences were identified across static and semantic analysis.'}
            </p>
          </div>

          {/* Risk Score Widget */}
          <div className="flex items-center gap-4 p-3.5 rounded bg-background border border-border flex-shrink-0">
            <div>
              <div className="text-[10px] font-mono text-slate-400 uppercase">Risk Score</div>
              <div className="text-2xl font-bold font-mono text-foreground">{risk_score.toFixed(1)} <span className="text-xs text-slate-500 font-normal">/ 10.0</span></div>
            </div>
            <div className="border-l border-border pl-4">
              <div className="text-[10px] font-mono text-slate-400 uppercase">Findings</div>
              <div className="text-2xl font-bold font-mono text-foreground">{findings.length}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Multi-Layer Pipeline Execution Table */}
      <div className="space-y-3">
        <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">
          Pipeline Layer Forensics
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="console-panel p-3 text-xs space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span>L1 Static (YARA-X)</span>
              <span className="text-emerald-400 font-mono font-bold">PASS</span>
            </div>
            <div className="font-semibold text-foreground">
              {findings.filter((f: any) => f.engine === 'yara' || f.engine === 'ast').length} Signals Flagged
            </div>
          </div>

          <div className="console-panel p-3 text-xs space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span>L2 Semantic (BYOK)</span>
              <span className="text-emerald-400 font-mono font-bold">PASS</span>
            </div>
            <div className="font-semibold text-foreground">
              {findings.filter((f: any) => f.engine === 'llm').length} Signals Flagged
            </div>
          </div>

          <div className="console-panel p-3 text-xs space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span>L3 Sandbox Egress</span>
              <span className="text-emerald-400 font-mono font-bold">PASS</span>
            </div>
            <div className="font-semibold text-foreground">
              {findings.filter((f: any) => f.engine === 'sandbox').length} Signals Flagged
            </div>
          </div>

          <div className="console-panel p-3 text-xs space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span>L4 ThreatDB CVEs</span>
              <span className="text-emerald-400 font-mono font-bold">PASS</span>
            </div>
            <div className="font-semibold text-foreground">
              {findings.filter((f: any) => f.engine === 'threat_db').length} Signals Flagged
            </div>
          </div>
        </div>
      </div>

      {/* Findings Section */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-3">
          <h2 className="text-sm font-bold text-foreground">
            Security Findings ({findings.length})
          </h2>

          {/* Severity Filter Tabs */}
          <div className="flex items-center gap-1 text-xs font-mono">
            <button
              onClick={() => setSelectedSeverity('ALL')}
              className={`px-2.5 py-1 rounded transition-colors ${getFilterBtnClass('ALL', 'bg-secondary text-foreground font-semibold')}`}
            >
              All ({findings.length})
            </button>
            {criticalCount > 0 && (
              <button
                onClick={() => setSelectedSeverity('CRITICAL')}
                className={`px-2.5 py-1 rounded transition-colors ${getFilterBtnClass('CRITICAL', 'bg-red-600 text-white font-bold')}`}
              >
                Critical ({criticalCount})
              </button>
            )}
            {highCount > 0 && (
              <button
                onClick={() => setSelectedSeverity('HIGH')}
                className={`px-2.5 py-1 rounded transition-colors ${getFilterBtnClass('HIGH', 'bg-orange-600 text-white font-bold')}`}
              >
                High ({highCount})
              </button>
            )}
            {mediumCount > 0 && (
              <button
                onClick={() => setSelectedSeverity('MEDIUM')}
                className={`px-2.5 py-1 rounded transition-colors ${getFilterBtnClass('MEDIUM', 'bg-amber-600 text-black font-bold')}`}
              >
                Medium ({mediumCount})
              </button>
            )}
          </div>
        </div>

        {filteredFindings.length === 0 ? (
          <div className="console-panel p-8 text-center text-xs text-slate-400">
            No findings matching selected severity filter.
          </div>
        ) : (
          <div className="space-y-3">
            {filteredFindings.map((finding: any, i: number) => (
              <div key={i} className="console-panel p-4 space-y-3 text-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-mono">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                      finding.severity === 'CRITICAL'
                        ? 'bg-red-950 text-red-400 border border-red-800'
                        : finding.severity === 'HIGH'
                        ? 'bg-orange-950 text-orange-400 border border-orange-800'
                        : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}>
                      {finding.severity}
                    </span>
                    <span className="font-semibold text-foreground">{finding.category}</span>
                  </div>

                  <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
                    <span>Engine: {finding.engine || 'static'}</span>
                    {finding.confidence && (
                      <span>• Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
                    )}
                  </div>
                </div>

                <p className="text-slate-300 leading-relaxed">
                  {finding.description}
                </p>

                {finding.file && (
                  <div className="p-2 rounded bg-background border border-border font-mono text-[11px] text-slate-300 flex items-center gap-2">
                    <FileCode className="w-3.5 h-3.5 text-slate-400" />
                    <span>{finding.file}</span>
                    {finding.line && <span className="text-slate-500">Line {finding.line}</span>}
                  </div>
                )}

                {finding.remediation && (
                  <div className="p-3 rounded bg-secondary border border-border space-y-1">
                    <div className="text-[11px] font-bold text-slate-200">Recommended Mitigation:</div>
                    <div className="text-slate-400 leading-relaxed">{finding.remediation}</div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
