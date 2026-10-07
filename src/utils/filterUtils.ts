import { Card } from '../types';

export function matchesCardFilter(
  card: Card,
  options: {
    searchQuery?: string;
    priority?: string;
    tagId?: string;
    assigneeId?: string;
    createdDatePreset?: string;
    startDate?: string;
    endDate?: string;
  }
): boolean {
  const {
    searchQuery = '',
    priority = 'all',
    tagId = 'all',
    assigneeId = 'all',
    createdDatePreset = 'all',
    startDate,
    endDate
  } = options;

  // 1. Text Search (title, description, tag labels, assignee names, or card ID)
  if (searchQuery.trim()) {
    const q = searchQuery.trim().toLowerCase();
    const matchesTitle = (card.title || '').toLowerCase().includes(q);
    const matchesDesc = (card.description || '').toLowerCase().includes(q);
    const matchesTags = Boolean(
      card.tags &&
      Array.isArray(card.tags) &&
      card.tags.some(t => ((t && t.label) || (t && (t as any).name) || '').toLowerCase().includes(q))
    );
    const matchesId = (card.id || '').toLowerCase().includes(q);
    if (!matchesTitle && !matchesDesc && !matchesTags && !matchesId) {
      return false;
    }
  }

  // 2. Priority Filter
  if (priority && priority !== 'all') {
    if (card.priority !== priority) {
      return false;
    }
  }

  // 3. Tag Filter
  if (tagId && tagId !== 'all') {
    if (tagId === 'none') {
      if (card.tags && card.tags.length > 0) return false;
    } else {
      if (!card.tags || !card.tags.some(t => t.id === tagId)) {
        return false;
      }
    }
  }

  // 4. Assignee / User Filter
  if (assigneeId && assigneeId !== 'all') {
    if (assigneeId === 'unassigned') {
      if (card.assigneeIds && card.assigneeIds.length > 0) return false;
    } else {
      if (!card.assigneeIds || !card.assigneeIds.includes(assigneeId)) {
        return false;
      }
    }
  }

  // 5. Creation Date Filter
  if (createdDatePreset && createdDatePreset !== 'all') {
    const cardCreatedTime = new Date(card.createdAt).getTime();
    if (isNaN(cardCreatedTime)) return true;

    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();

    if (createdDatePreset === 'today') {
      if (cardCreatedTime < todayStart) return false;
    } else if (createdDatePreset === 'last_7_days') {
      const sevenDaysAgo = todayStart - (7 * 24 * 60 * 60 * 1000);
      if (cardCreatedTime < sevenDaysAgo) return false;
    } else if (createdDatePreset === 'last_30_days') {
      const thirtyDaysAgo = todayStart - (30 * 24 * 60 * 60 * 1000);
      if (cardCreatedTime < thirtyDaysAgo) return false;
    } else if (createdDatePreset === 'custom') {
      if (startDate) {
        const start = new Date(startDate).getTime();
        if (!isNaN(start) && cardCreatedTime < start) return false;
      }
      if (endDate) {
        // End of the selected day (23:59:59.999)
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        const endTime = end.getTime();
        if (!isNaN(endTime) && cardCreatedTime > endTime) return false;
      }
    }
  }

  return true;
}
