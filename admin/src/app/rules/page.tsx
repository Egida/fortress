'use client';

import { useCallback, useEffect, useState } from 'react';
import { fortressGet, fortressPost, fortressPut, fortressDelete } from '@/lib/api';
import type { ProtectionRule } from '@/lib/types';
import {
  ScrollText,
  Plus,
  X,
  Pencil,
  Trash2,
  Save,
  Search,
} from 'lucide-react';

const ACTION_OPTIONS = ['Pass', 'Challenge', 'Block', 'Tarpit'] as const;
type Action = (typeof ACTION_OPTIONS)[number];

const ACTION_COLORS: Record<string, string> = {
  Pass: 'bg-green-600/20 text-green-400',
  Challenge: 'bg-yellow-600/20 text-yellow-400',
  Block: 'bg-red-600/20 text-red-400',
  Tarpit: 'bg-purple-600/20 text-purple-400',
};

interface RuleFormState {
  name: string;
  priority: string;
  conditions: string;
  action: Action;
}

const emptyForm: RuleFormState = {
  name: '',
  priority: '0',
  conditions: '{}',
  action: 'Block',
};

export default function RulesPage() {
  const [rules, setRules] = useState<ProtectionRule[]>([]);
  const [loading, setLoading] = useState(false);

  // Add form
  const [showAddForm, setShowAddForm] = useState(false);
  const [addForm, setAddForm] = useState<RuleFormState>({ ...emptyForm });
  const [addError, setAddError] = useState('');

  // Edit form
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editForm, setEditForm] = useState<RuleFormState>({ ...emptyForm });
  const [editError, setEditError] = useState('');

  // --------------- Styles ---------------
  const inputClass =
    'bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 w-full focus:outline-none focus:border-zinc-500 transition-colors';

  const primaryBtn =
    'bg-blue-600 hover:bg-blue-700 text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors';

  const dangerBtn =
    'bg-red-600/20 text-red-400 hover:bg-red-600/30 rounded-lg px-3 py-1 text-xs font-medium transition-colors';

  const thClass = 'text-left text-xs font-medium text-zinc-400 uppercase tracking-wider px-4 py-3';
  const tdClass = 'px-4 py-3 text-sm text-zinc-300';

  // --------------- Fetch ---------------
  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fortressGet<{ rules: ProtectionRule[] }>('/api/fortress/rules');
      setRules(data.rules);
    } catch (err) {
      console.error('Failed to fetch rules', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  // --------------- Create ---------------
  const createRule = async () => {
    setAddError('');
    if (!addForm.name.trim()) {
      setAddError('Rule identifier is required.');
      return;
    }

    let parsedConditions: unknown;
    try {
      parsedConditions = JSON.parse(addForm.conditions);
    } catch {
      setAddError('Invalid JSON format in match condition.');
      return;
    }

    try {
      await fortressPost('/api/fortress/rules', {
        name: addForm.name,
        condition: parsedConditions,
        action: addForm.action,
        priority: Number(addForm.priority),
      });
      setAddForm({ ...emptyForm });
      setShowAddForm(false);
      fetchRules();
    } catch (err) {
      console.error('Failed to create rule', err);
      setAddError('An error occurred while creating the rule.');
    }
  };

  // --------------- Update ---------------
  const startEdit = (rule: ProtectionRule) => {
    setEditingId(rule.id);
    setEditError('');
    setEditForm({
      name: rule.name,
      priority: String(rule.priority),
      conditions: (() => {
        try {
          return JSON.stringify(JSON.parse(rule.conditions_json), null, 2);
        } catch {
          return rule.conditions_json;
        }
      })(),
      action: rule.action as Action,
    });
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditError('');
  };

  const saveEdit = async (rule: ProtectionRule) => {
    setEditError('');

    let parsedConditions: unknown;
    try {
      parsedConditions = JSON.parse(editForm.conditions);
    } catch {
      setEditError('Invalid JSON format in match condition.');
      return;
    }

    try {
      await fortressPut('/api/fortress/rules/' + rule.id, {
        name: editForm.name,
        condition: parsedConditions,
        action: editForm.action,
        priority: Number(editForm.priority),
        enabled: rule.enabled,
      });
      setEditingId(null);
      fetchRules();
    } catch (err) {
      console.error('Failed to update rule', err);
      setEditError('An error occurred while updating the rule.');
    }
  };

  // --------------- Toggle enabled ---------------
  const toggleEnabled = async (rule: ProtectionRule) => {
    try {
      let parsedConditions: unknown;
      try {
        parsedConditions = JSON.parse(rule.conditions_json);
      } catch {
        parsedConditions = rule.conditions_json;
      }

      await fortressPut('/api/fortress/rules/' + rule.id, {
        name: rule.name,
        condition: parsedConditions,
        action: rule.action,
        priority: rule.priority,
        enabled: !rule.enabled,
      });
      fetchRules();
    } catch (err) {
      console.error('Failed to toggle rule state', err);
    }
  };

  // --------------- Delete ---------------
  const deleteRule = async (id: number) => {
    if (!confirm('Are you sure you want to delete this rule? This action cannot be undone.')) return;
    try {
      await fortressDelete('/api/fortress/rules/' + id);
      fetchRules();
    } catch (err) {
      console.error('Failed to delete rule', err);
    }
  };

  // --------------- Helpers ---------------
  const formatConditions = (json: string): string => {
    try {
      return JSON.stringify(JSON.parse(json), null, 2);
    } catch {
      return json;
    }
  };

  const actionBadge = (action: string) => {
    const color = ACTION_COLORS[action] ?? 'bg-zinc-700 text-zinc-300';
    return (
      <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ${color}`}>
        {action}
      </span>
    );
  };

  // --------------- Render ---------------
  return (
    <div className="min-h-screen bg-black text-zinc-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-violet-500/10 ring-1 ring-violet-500/20">
              <ScrollText className="h-5 w-5 text-violet-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white">Rule Engine</h1>
              <p className="text-sm text-zinc-500">
                Custom protection rules and conditional response logic
              </p>
            </div>
          </div>
        </div>
        <button
          className={`${primaryBtn} inline-flex items-center gap-1.5`}
          onClick={() => {
            setShowAddForm((v) => !v);
            setAddError('');
            if (showAddForm) setAddForm({ ...emptyForm });
          }}
        >
          {showAddForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          {showAddForm ? 'Cancel' : 'Create Rule'}
        </button>
      </div>

      {/* Add form */}
      {showAddForm && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 space-y-4">
          <h2 className="text-lg font-semibold text-zinc-100">Create New Rule</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Rule Identifier</label>
              <input
                type="text"
                className={inputClass}
                placeholder="e.g. block-admin-brute-force"
                value={addForm.name}
                onChange={(e) => setAddForm({ ...addForm, name: e.target.value })}
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Priority</label>
              <input
                type="number"
                className={inputClass}
                placeholder="0"
                value={addForm.priority}
                onChange={(e) => setAddForm({ ...addForm, priority: e.target.value })}
              />
            </div>
          </div>

          <div>
            <label className="block text-xs text-zinc-400 mb-1">Match Condition (JSON)</label>
            <textarea
              className={`${inputClass} font-mono text-sm min-h-[120px] resize-y`}
              placeholder='{"path": "/api/*", "method": "POST"}'
              value={addForm.conditions}
              onChange={(e) => setAddForm({ ...addForm, conditions: e.target.value })}
            />
          </div>

          <div>
            <label className="block text-xs text-zinc-400 mb-1">Response Action</label>
            <select
              className={inputClass}
              value={addForm.action}
              onChange={(e) => setAddForm({ ...addForm, action: e.target.value as Action })}
            >
              {ACTION_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>

          {addError && (
            <p className="text-sm text-red-400">{addError}</p>
          )}

          <button className={`${primaryBtn} inline-flex items-center gap-1.5`} onClick={createRule}>
            <Save className="h-4 w-4" />
            Save Rule
          </button>
        </div>
      )}

      {/* Rules table */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-12 space-y-3">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-zinc-700 border-t-zinc-400" />
            <p className="text-zinc-500 text-sm">Loading rules...</p>
          </div>
        ) : rules.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
            <ScrollText className="h-12 w-12 mb-4 text-zinc-700" />
            <p className="text-sm text-zinc-500">No protection rules configured yet.</p>
            <p className="text-xs text-zinc-600 mt-1">Create your first rule to get started.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-zinc-800">
                <tr>
                  <th className={thClass}>Rule Identifier</th>
                  <th className={thClass}>Priority</th>
                  <th className={thClass}>Match Condition</th>
                  <th className={thClass}>Response Action</th>
                  <th className={thClass}>Status</th>
                  <th className={thClass}>Operations</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-zinc-800/30 transition-colors align-top">
                    {editingId === rule.id ? (
                      <>
                        {/* Inline edit row */}
                        <td className={tdClass}>
                          <input
                            type="text"
                            className={inputClass}
                            value={editForm.name}
                            onChange={(e) =>
                              setEditForm({ ...editForm, name: e.target.value })
                            }
                          />
                        </td>
                        <td className={tdClass}>
                          <input
                            type="number"
                            className={`${inputClass} w-20`}
                            value={editForm.priority}
                            onChange={(e) =>
                              setEditForm({ ...editForm, priority: e.target.value })
                            }
                          />
                        </td>
                        <td className={tdClass}>
                          <textarea
                            className={`${inputClass} font-mono text-xs min-h-[80px] resize-y`}
                            value={editForm.conditions}
                            onChange={(e) =>
                              setEditForm({ ...editForm, conditions: e.target.value })
                            }
                          />
                          {editError && (
                            <p className="text-xs text-red-400 mt-1">{editError}</p>
                          )}
                        </td>
                        <td className={tdClass}>
                          <select
                            className={inputClass}
                            value={editForm.action}
                            onChange={(e) =>
                              setEditForm({ ...editForm, action: e.target.value as Action })
                            }
                          >
                            {ACTION_OPTIONS.map((opt) => (
                              <option key={opt} value={opt}>
                                {opt}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td className={tdClass}>
                          <button
                            onClick={() => toggleEnabled(rule)}
                            className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors ${
                              rule.enabled
                                ? 'bg-green-600/20 text-green-400'
                                : 'bg-zinc-700/50 text-zinc-500'
                            }`}
                          >
                            {rule.enabled ? 'Active' : 'Inactive'}
                          </button>
                        </td>
                        <td className={tdClass}>
                          <div className="flex gap-2">
                            <button
                              className={`${primaryBtn} inline-flex items-center gap-1`}
                              onClick={() => saveEdit(rule)}
                            >
                              <Save className="h-3 w-3" />
                              Save
                            </button>
                            <button
                              className="bg-zinc-700 hover:bg-zinc-600 text-zinc-300 rounded-lg px-3 py-1 text-xs font-medium transition-colors"
                              onClick={cancelEdit}
                            >
                              Cancel
                            </button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        {/* Display row */}
                        <td className={tdClass}>
                          <span className="font-medium text-zinc-100">{rule.name}</span>
                        </td>
                        <td className={tdClass}>
                          <span className="font-mono">{rule.priority}</span>
                        </td>
                        <td className={tdClass}>
                          <pre className="bg-zinc-800 rounded-lg p-2 text-xs text-zinc-400 font-mono overflow-x-auto max-w-xs whitespace-pre-wrap">
                            {formatConditions(rule.conditions_json)}
                          </pre>
                        </td>
                        <td className={tdClass}>{actionBadge(rule.action)}</td>
                        <td className={tdClass}>
                          <button
                            onClick={() => toggleEnabled(rule)}
                            className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium cursor-pointer transition-colors ${
                              rule.enabled
                                ? 'bg-green-600/20 text-green-400'
                                : 'bg-zinc-700/50 text-zinc-500'
                            }`}
                          >
                            {rule.enabled ? 'Active' : 'Inactive'}
                          </button>
                        </td>
                        <td className={tdClass}>
                          <div className="flex gap-2">
                            <button
                              className="inline-flex items-center gap-1 bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 rounded-lg px-3 py-1 text-xs font-medium transition-colors"
                              onClick={() => startEdit(rule)}
                            >
                              <Pencil className="h-3 w-3" />
                              Edit
                            </button>
                            <button
                              className={`inline-flex items-center gap-1 ${dangerBtn}`}
                              onClick={() => deleteRule(rule.id)}
                            >
                              <Trash2 className="h-3 w-3" />
                              Delete
                            </button>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
