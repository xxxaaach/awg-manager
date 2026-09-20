<script lang="ts">
	import { api } from '$lib/api/client';
	import Button from '$lib/components/ui/Button.svelte';
	import type { AmneziaPremiumCatalog } from '$lib/types';
	import PremiumCountryList from './PremiumCountryList.svelte';

	interface Props {
		backendAvailability?: { nativewg: boolean; kernel: boolean };
	}

	let { backendAvailability }: Props = $props();

	let open = $state(false);
	let loading = $state(false);
	let busy = $state(false);
	let catalog = $state<AmneziaPremiumCatalog | null>(null);
	let errorText = $state('');
	let protocol = $state<'awg' | 'vless'>('awg');
	let selectedCountry = $state('');

	const gateway = $derived(catalog?.gateway === true);
	const chosenBackend = $derived<'nativewg' | 'kernel'>(
		catalog?.awgBackend === 'kernel' && backendAvailability?.kernel !== false
			? 'kernel'
			: backendAvailability?.nativewg !== false
				? 'nativewg'
				: 'kernel'
	);
	const activeLabel = $derived(
		catalog?.gateway && catalog.currentCountry
			? catalog.currentCountry.toUpperCase() + ' · ' + (catalog.currentProtocol ?? 'awg').toUpperCase()
			: 'Быстро'
	);
	const canApply = $derived(
		gateway &&
			selectedCountry !== '' &&
			!busy &&
			(protocol === 'vless' || backendAvailability?.nativewg !== false || backendAvailability?.kernel !== false)
	);

	async function toggle(): Promise<void> {
		if (open) {
			open = false;
			return;
		}
		open = true;
		if (catalog || loading) return;
		await load();
	}

	async function load(): Promise<void> {
		loading = true;
		errorText = '';
		try {
			const data = await api.amneziaPremiumCatalog();
			catalog = data;
			if (data.gateway) {
				protocol = data.currentProtocol === 'vless' ? 'vless' : 'awg';
				selectedCountry = data.currentCountry ?? '';
			}
		} catch (e) {
			errorText = e instanceof Error ? e.message : 'Не удалось загрузить Amnezia Premium';
		} finally {
			loading = false;
		}
	}

	function setProtocol(next: 'awg' | 'vless'): void {
		protocol = next;
		if (!catalog || !selectedCountry) return;
		const country = catalog.countries.find(
			(c) => c.code.trim().toLowerCase() === selectedCountry.trim().toLowerCase()
		);
		if (!country?.protocols) return;
		const supported = country.protocols.some((p) => p.trim().toLowerCase() === next);
		if (!supported) selectedCountry = '';
	}

	async function apply(): Promise<void> {
		if (!canApply) return;
		busy = true;
		errorText = '';
		try {
			await api.amneziaPremiumSwitch(selectedCountry, protocol, chosenBackend);
			if (catalog) {
				catalog = {
					...catalog,
					currentCountry: selectedCountry,
					currentProtocol: protocol,
					awgBackend: chosenBackend
				};
			}
			open = false;
		} catch (e) {
			errorText = e instanceof Error ? e.message : 'Не удалось переключить Premium';
		} finally {
			busy = false;
		}
	}

	function close(): void {
		if (!busy) open = false;
	}
</script>

<div class="premium-quick">
	<Button variant="secondary" size="sm" onclick={() => void toggle()}>
		{activeLabel} ▾
	</Button>

	{#if open}
		<button class="premium-quick-backdrop" type="button" aria-label="Закрыть" onclick={close}></button>
		<div class="premium-quick-panel" role="dialog" aria-label="Быстрое переключение Amnezia Premium">
			<div class="premium-quick-head">
				<strong>Amnezia Premium</strong>
				<button type="button" class="premium-quick-close" aria-label="Закрыть" onclick={close}>×</button>
			</div>

			{#if loading}
				<p class="premium-quick-muted">Загрузка…</p>
			{:else if errorText}
				<p class="premium-quick-error">{errorText}</p>
				<Button variant="secondary" size="sm" onclick={() => void load()}>Повторить</Button>
			{:else if !gateway}
				<p class="premium-quick-muted">
					Быстрое переключение доступно для ключей Amnezia Premium V2 (Gateway).
				</p>
			{:else if catalog}
				<div class="premium-quick-protocol" role="group" aria-label="Протокол">
					<button
						type="button"
						class:active={protocol === 'awg'}
						disabled={busy}
						onclick={() => setProtocol('awg')}>AWG</button
					>
					<button
						type="button"
						class:active={protocol === 'vless'}
						disabled={busy}
						onclick={() => setProtocol('vless')}>VLESS</button
					>
				</div>

				<PremiumCountryList
					countries={catalog.countries}
					issued={[]}
					countryTunnels={[]}
					selected={selectedCountry}
					disabled={busy}
					{protocol}
					onselect={(code) => (selectedCountry = code)}
				/>

				<div class="premium-quick-actions">
					<Button variant="secondary" size="md" disabled={busy} onclick={close}>Отмена</Button>
					<Button variant="primary" size="md" disabled={!canApply} onclick={() => void apply()}>
						{busy ? 'Переключение…' : 'Подключить'}
					</Button>
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.premium-quick {
		position: relative;
		display: inline-flex;
	}

	.premium-quick-backdrop {
		position: fixed;
		inset: 0;
		z-index: 89;
		border: 0;
		background: transparent;
	}

	.premium-quick-panel {
		position: absolute;
		z-index: 90;
		top: calc(100% + 8px);
		right: 0;
		width: min(390px, calc(100vw - 24px));
		max-height: min(620px, calc(100vh - 100px));
		overflow: auto;
		display: flex;
		flex-direction: column;
		gap: 10px;
		padding: 12px;
		border: 1px solid var(--border, var(--color-border));
		border-radius: 10px;
		background: var(--bg-primary, var(--color-bg-primary));
		box-shadow: 0 14px 40px rgb(0 0 0 / 0.2);
	}

	.premium-quick-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}

	.premium-quick-close {
		width: 32px;
		height: 32px;
		border: 0;
		border-radius: 6px;
		background: transparent;
		color: var(--text-secondary, var(--color-text-secondary));
		font-size: 1.35rem;
		cursor: pointer;
	}

	.premium-quick-protocol {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 4px;
		padding: 3px;
		border-radius: 8px;
		background: var(--bg-secondary, var(--color-bg-secondary));
	}

	.premium-quick-protocol button {
		min-height: 34px;
		border: 0;
		border-radius: 6px;
		background: transparent;
		color: var(--text-secondary, var(--color-text-secondary));
		cursor: pointer;
	}

	.premium-quick-protocol button.active {
		background: var(--bg-primary, var(--color-bg-primary));
		color: var(--text-primary, var(--color-text-primary));
		box-shadow: 0 0 0 1px var(--border, var(--color-border));
	}

	.premium-quick-actions {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 8px;
	}

	.premium-quick-muted,
	.premium-quick-error {
		margin: 0;
		font-size: 0.8125rem;
		line-height: 1.45;
	}

	.premium-quick-muted {
		color: var(--text-secondary, var(--color-text-secondary));
	}

	.premium-quick-error {
		color: var(--error, var(--color-error));
	}

	@media (max-width: 640px) {
		.premium-quick-panel {
			position: fixed;
			top: auto;
			left: 10px;
			right: 10px;
			bottom: max(10px, env(safe-area-inset-bottom));
			width: auto;
			max-height: min(78vh, 680px);
			border-radius: 14px;
			padding: 14px;
		}

		.premium-quick-backdrop {
			background: rgb(0 0 0 / 0.34);
		}

		.premium-quick-actions {
			position: sticky;
			bottom: 0;
			padding-top: 6px;
			background: var(--bg-primary, var(--color-bg-primary));
		}
	}
</style>
