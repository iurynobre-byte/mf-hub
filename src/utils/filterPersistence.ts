import { User, UserFilterPreferences } from '../types';
import { saveUserFilterPreferences } from '../services/firestoreService';

export const DEFAULT_USER_FILTERS: UserFilterPreferences = {
  searchQuery: '',
  selectedPriority: 'all',
  selectedTagId: 'all',
  selectedAssigneeId: 'all',
  createdDatePreset: 'all',
  startDate: '',
  endDate: '',
  activeBoardId: undefined
};

const getStorageKey = (userId: string) => `flowdeck_user_filters_${userId}`;

/**
 * Carrega os filtros salvos do usuário a partir do localStorage ou do perfil Firestore.
 */
export function loadStoredUserFilters(
  userId: string,
  userDocFallback?: User | null
): UserFilterPreferences {
  if (!userId) return { ...DEFAULT_USER_FILTERS };

  // 1. Tenta carregar do localStorage instantâneo
  try {
    const rawLocal = localStorage.getItem(getStorageKey(userId));
    if (rawLocal) {
      const parsed = JSON.parse(rawLocal);
      return {
        searchQuery: typeof parsed.searchQuery === 'string' ? parsed.searchQuery : '',
        selectedPriority: typeof parsed.selectedPriority === 'string' ? parsed.selectedPriority : 'all',
        selectedTagId: typeof parsed.selectedTagId === 'string' ? parsed.selectedTagId : 'all',
        selectedAssigneeId: typeof parsed.selectedAssigneeId === 'string' ? parsed.selectedAssigneeId : 'all',
        createdDatePreset: typeof parsed.createdDatePreset === 'string' ? parsed.createdDatePreset : 'all',
        startDate: typeof parsed.startDate === 'string' ? parsed.startDate : '',
        endDate: typeof parsed.endDate === 'string' ? parsed.endDate : '',
        activeBoardId: typeof parsed.activeBoardId === 'string' ? parsed.activeBoardId : undefined,
        updatedAt: parsed.updatedAt
      };
    }
  } catch (err) {
    console.warn('[FilterPersistence] Error parsing localStorage filters:', err);
  }

  // 2. Se não houver no localStorage deste dispositivo, tenta as preferências sincronizadas do usuário
  if (userDocFallback?.filterPreferences) {
    const remote = userDocFallback.filterPreferences;
    const resolved: UserFilterPreferences = {
      searchQuery: remote.searchQuery || '',
      selectedPriority: remote.selectedPriority || 'all',
      selectedTagId: remote.selectedTagId || 'all',
      selectedAssigneeId: remote.selectedAssigneeId || 'all',
      createdDatePreset: remote.createdDatePreset || 'all',
      startDate: remote.startDate || '',
      endDate: remote.endDate || '',
      activeBoardId: remote.activeBoardId || undefined,
      updatedAt: remote.updatedAt
    };
    try {
      localStorage.setItem(getStorageKey(userId), JSON.stringify(resolved));
    } catch {
      // Ignora erro de cota de storage local
    }
    return resolved;
  }

  return { ...DEFAULT_USER_FILTERS };
}

// Timer para debounce de sincronização no Firestore (evita requisições excessivas durante digitação)
const debounceTimers: Record<string, any> = {};

/**
 * Salva os filtros do usuário no localStorage e sincroniza na nuvem (Firestore) no documento do usuário.
 */
export function persistUserFilters(
  userId: string,
  filters: UserFilterPreferences,
  debounceMs: number = 400
): void {
  if (!userId) return;

  const toSave: UserFilterPreferences = {
    searchQuery: filters.searchQuery || '',
    selectedPriority: filters.selectedPriority || 'all',
    selectedTagId: filters.selectedTagId || 'all',
    selectedAssigneeId: filters.selectedAssigneeId || 'all',
    createdDatePreset: filters.createdDatePreset || 'all',
    startDate: filters.startDate || '',
    endDate: filters.endDate || '',
    activeBoardId: filters.activeBoardId,
    updatedAt: new Date().toISOString()
  };

  // Salva de forma imediata no localStorage
  try {
    localStorage.setItem(getStorageKey(userId), JSON.stringify(toSave));
  } catch (e) {
    console.warn('[FilterPersistence] Error saving to localStorage:', e);
  }

  // Sincroniza no Firestore de forma assíncrona com debounce
  if (debounceTimers[userId]) {
    clearTimeout(debounceTimers[userId]);
  }

  debounceTimers[userId] = setTimeout(() => {
    saveUserFilterPreferences(userId, toSave).catch(err => {
      console.warn('[FilterPersistence] Error syncing to Firestore:', err);
    });
    delete debounceTimers[userId];
  }, debounceMs);
}

/**
 * Reseta os filtros salvos do usuário para o padrão limpo.
 */
export function resetStoredUserFilters(userId: string): void {
  if (!userId) return;
  const cleanFilters: UserFilterPreferences = {
    ...DEFAULT_USER_FILTERS,
    updatedAt: new Date().toISOString()
  };

  try {
    localStorage.setItem(getStorageKey(userId), JSON.stringify(cleanFilters));
  } catch {
    // Ignora
  }

  saveUserFilterPreferences(userId, cleanFilters).catch(console.warn);
}
