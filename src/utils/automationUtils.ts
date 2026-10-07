import { AutomationSchedule, CardAutomationDateConfig, CardAutomationRule } from '../types';

/**
 * Calculates human-readable description for an automation schedule rule.
 */
export function getScheduleDescription(schedule: AutomationSchedule): string {
  const timeStr = schedule.time ? ` às ${schedule.time}` : '';
  
  if (schedule.frequency === 'daily') {
    if (schedule.dailyType === 'workdays_only') {
      return `Todos os dias úteis (Segunda a Sexta)${timeStr}`;
    }
    return `Todos os dias (Diário)${timeStr}`;
  }

  if (schedule.frequency === 'weekly') {
    const daysMap: { [k: number]: string } = {
      0: 'Dom',
      1: 'Seg',
      2: 'Ter',
      3: 'Qua',
      4: 'Qui',
      5: 'Sex',
      6: 'Sáb'
    };
    const days = (schedule.weeklyDays || [1])
      .sort((a, b) => a - b)
      .map(d => daysMap[d] || `Dia ${d}`);

    return `Semanalmente (${days.join(', ')})${timeStr}`;
  }

  if (schedule.frequency === 'monthly') {
    if (schedule.monthlyType === 'workday_of_month') {
      if (schedule.workdayOfMonth === 'last_workday') {
        return `Mensalmente no Último dia útil do mês${timeStr}`;
      }
      return `Mensalmente no ${schedule.workdayOfMonth}º dia útil do mês${timeStr}`;
    }
    return `Mensalmente todo dia ${schedule.dayOfMonth || 1}${timeStr}`;
  }

  return `Personalizado${timeStr}`;
}

/**
 * Calculates start and due dates for a generated card based on dynamic rule parameters:
 * - 'none': null
 * - 'today': today's date
 * - 'tomorrow': today + 1 day
 * - 'd_plus': today + X days offset
 * - 'fixed': specific fixed date
 */
export function calculateAutomationDates(
  dateConfig: CardAutomationDateConfig,
  baseDate = new Date()
): { startDate: string | null; dueDate: string | null } {
  let startDate: string | null = null;
  let dueDate: string | null = null;

  // Process Start Date
  if (dateConfig.startDateType === 'today') {
    const d = new Date(baseDate);
    startDate = formatISODateTime(d, dateConfig.startTime);
  } else if (dateConfig.startDateType === 'tomorrow') {
    const d = new Date(baseDate);
    d.setDate(d.getDate() + 1);
    startDate = formatISODateTime(d, dateConfig.startTime);
  } else if (dateConfig.startDateType === 'd_plus') {
    const offset = Math.max(0, Number(dateConfig.startDateDaysOffset) || 0);
    const d = new Date(baseDate);
    d.setDate(d.getDate() + offset);
    startDate = formatISODateTime(d, dateConfig.startTime);
  } else if (dateConfig.startDateType === 'fixed' && dateConfig.startDateFixed) {
    startDate = combineDateAndTimeString(dateConfig.startDateFixed, dateConfig.startTime);
  }

  // Process Due Date
  if (dateConfig.dueDateType === 'today') {
    const d = new Date(baseDate);
    dueDate = formatISODateTime(d, dateConfig.dueTime);
  } else if (dateConfig.dueDateType === 'tomorrow') {
    const d = new Date(baseDate);
    d.setDate(d.getDate() + 1);
    dueDate = formatISODateTime(d, dateConfig.dueTime);
  } else if (dateConfig.dueDateType === 'd_plus') {
    const offset = Math.max(0, Number(dateConfig.dueDateDaysOffset) || 0);
    const d = new Date(baseDate);
    d.setDate(d.getDate() + offset);
    dueDate = formatISODateTime(d, dateConfig.dueTime);
  } else if (dateConfig.dueDateType === 'fixed' && dateConfig.dueDateFixed) {
    dueDate = combineDateAndTimeString(dateConfig.dueDateFixed, dateConfig.dueTime);
  }

  return { startDate, dueDate };
}

function formatISODateTime(date: Date, timeStr?: string): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  
  if (timeStr && /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(timeStr)) {
    return `${y}-${m}-${d}T${timeStr}:00Z`;
  }
  return `${y}-${m}-${d}T18:00:00Z`;
}

function combineDateAndTimeString(dateStr: string, timeStr?: string): string {
  const cleanDate = dateStr.substring(0, 10);
  if (timeStr && /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(timeStr)) {
    return `${cleanDate}T${timeStr}:00Z`;
  }
  return `${cleanDate}T18:00:00Z`;
}

/**
 * Replace placeholders like {{data}}, {{mes}}, {{ano}} in card title and description
 */
export function interpolateVariables(template: string, baseDate = new Date()): string {
  if (!template) return '';
  const day = String(baseDate.getDate()).padStart(2, '0');
  const monthNames = [
    'Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho',
    'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'
  ];
  const monthNum = String(baseDate.getMonth() + 1).padStart(2, '0');
  const monthName = monthNames[baseDate.getMonth()];
  const year = String(baseDate.getFullYear());
  const dateFormatted = `${day}/${monthNum}/${year}`;

  return template
    .replace(/{{\s*data\s*}}/gi, dateFormatted)
    .replace(/{{\s*mes\s*}}/gi, monthName)
    .replace(/{{\s*mes_num\s*}}/gi, monthNum)
    .replace(/{{\s*ano\s*}}/gi, year);
}

export const INITIAL_AUTOMATIONS: CardAutomationRule[] = [
  {
    id: 'auto_daily_standup',
    title: '🚀 Daily Standup & Sincronização Matinal',
    description: 'Cria diariamente o cartão de acompanhamento de impedimentos e metas do dia para a equipe de engenharia.',
    boardId: 'board_core_sprint',
    columnId: 'col_todo',
    enabled: true,
    createdById: 'admin',
    createdByName: 'Administrador',
    createdByAvatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
    createdAt: '2026-08-25T08:00:00Z',
    lastRunAt: '2026-09-01T09:00:00Z',
    runCount: 7,
    cardTitle: 'Daily Scrum & Alinhamento de Metas - {{data}}',
    cardDescription: 'Rotina automática matinal para alinhamento de entregas, desbloqueio de tarefas e revisão do fluxo de trabalho diário.',
    priority: 'medium',
    tags: [
      { id: 'tag_infra', label: 'DevSecOps & CI/CD', color: 'sky' }
    ],
    assigneeIds: [],
    requester: 'Tech Lead / Scrum Master',
    requesterDepartment: 'Engenharia de Software',
    valueLevel: 'Médio',
    demandType: 'Rotina',
    checklist: [
      { id: 'auto_chk_1', title: 'O que foi entregue ontem e eventuais bloqueios', completed: false },
      { id: 'auto_chk_2', title: 'Prioridades e metas para o dia de hoje', completed: false },
      { id: 'auto_chk_3', title: 'Identificar itens com risco de atraso na sprint', completed: false }
    ],
    dateConfig: {
      startDateType: 'today',
      startTime: '09:00',
      dueDateType: 'today',
      dueTime: '18:00'
    },
    schedule: {
      frequency: 'daily',
      dailyType: 'workdays_only',
      time: '08:30'
    }
  },
  {
    id: 'auto_monthly_audit',
    title: '🛡️ Fechamento e Auditoria Mensal de Conformidade',
    description: 'Rotina agendada para o 1º dia útil de cada mês para consolidação das métricas de segurança e LGPD.',
    boardId: 'board_core_sprint',
    columnId: 'col_backlog',
    enabled: true,
    createdById: 'admin',
    createdByName: 'Administrador',
    createdByAvatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
    createdAt: '2026-08-20T10:00:00Z',
    lastRunAt: '2026-09-01T08:00:00Z',
    runCount: 2,
    cardTitle: 'Relatório Mensal de Segurança & Auditoria Zero-Leakage (Mês: {{mes}})',
    cardDescription: 'Consolidação mensal obrigatória de trilha de auditoria, rotação de chaves e indicadores de conformidade de infraestrutura.',
    priority: 'high',
    tags: [
      { id: 'tag_sec', label: 'Segurança / OWASP', color: 'rose' },
      { id: 'tag_compliance', label: 'Compliance & LGPD', color: 'amber' }
    ],
    assigneeIds: [],
    requester: 'Diretoria de Segurança & Riscos',
    requesterDepartment: 'Segurança da Informação & SOC',
    valueLevel: 'Alto',
    demandType: 'Rotina',
    checklist: [
      { id: 'auto_chk_m1', title: 'Auditar integridade de HMAC nos logs do período', completed: false },
      { id: 'auto_chk_m2', title: 'Revisar matriz de permissões e acessos ativos', completed: false },
      { id: 'auto_chk_m3', title: 'Exportar relatório executivo para diretoria', completed: false }
    ],
    dateConfig: {
      startDateType: 'today',
      startTime: '08:00',
      dueDateType: 'd_plus',
      dueDateDaysOffset: 5,
      dueTime: '18:00'
    },
    schedule: {
      frequency: 'monthly',
      monthlyType: 'workday_of_month',
      workdayOfMonth: 1,
      time: '08:00'
    }
  }
];
