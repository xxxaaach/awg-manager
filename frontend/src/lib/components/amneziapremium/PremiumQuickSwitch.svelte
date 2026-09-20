<script lang="ts">
	import { onMount } from 'svelte';
	import { ChevronDown, Settings2 } from 'lucide-svelte';
	import { api } from '$lib/api/client';
	import type { AmneziaPremiumCatalog } from '$lib/types';
	import { Button, Modal, SegmentedControl } from '$lib/components/ui';
	import DropdownMenu from '$lib/components/ui/DropdownMenu.svelte';
	import {
		isPremiumCountryAvailableForProtocol,
		premiumCountryFlag,
		type PremiumGatewayProtocol
	} from '$lib/utils/amneziaPremiumCatalog';

	interface Props {
		onmanage: () => void;
		onchanged?: () => void;
	}

	let { onmanage, onchanged }: Props = $props();

	let visible = $state(false);
	let loading = $state(true);
	let busy = $state(false);
	let mobileOpen = $state(false);
	let errorText = $state('');
	let catalog = $state<AmneziaPremiumCatalog | null>(null);
	let currentCountry = $state('');
	let currentProtocol = $state<PremiumGatewayProtocol>('awg');
	let draftProtocol = $state<PremiumGatewayProtocol>('awg');
	let awgBackend = $state<'nativewg' | 'kernel'>('nativewg');

	const protocolOptions = [
		{ value: 'awg' as const, label: 'AWG' },
		{ value: 'vless' as const, label: 'VLESS' }
	];

	const countries = $derived(
		(catalog?.countries ?? []).filter((country) =>
			isPremiumCountryAvailableForProtocol(country, draftProtocol)
		)
	);

	const activeCountry = $derived(
		catalog?.countries.find(
			(c) => c.code.trim().toLowerCase() === currentCountry.trim().toLowerCase()
		)
	);
	const label = $derived(
		currentCountry
			? `${premiumCountryFlag(currentCountry)} ${activeCountry?.name ?? currentCountry.toUpperCase()} · ${currentProtocol === 'vless' ? 'VLESS' : 'AWG'}`
			: 'Amnezia Premium'
	);

	onMount(() => {
		void load();
	});

	async function load(): Promise<void> {
		loading = true;
		errorText = '';
		try {
			const [state, data] = await Promise.all([
				api.amneziaPremiumGatewayState(),
				api.amneziaPremiumCatalog()
			]);
			catalog = data;
			currentCountry = state.countryCode || '';
			currentProtocol = state.protocol === 'vless' ? 'vless' : 'awg';
			draftProtocol = currentProtocol;
			awgBackend = state.awgBackend === 'kernel' ? 'kernel' : 'nativewg';
			visible = true;
		} catch {
			// No usable Premium account/session: the ordinary "Amnezia Premium"
			// management button remains available, so the quick control simply
			// stays out of the toolbar.
			visible = false;
		} finally {
			loading = false;
		}
	}

	function countrySupports(code: string, protocol: PremiumGatewayProtocol): boolean {
		const wanted = code.trim().toLowerCase();
		const country = catalog?.countries.find((c) => c.code.trim().toLowerCase() === wanted);
		return !!country && isPremiumCountryAvailableForProtocol(country, protocol);
	}

	async function selectProtocol(
		next: PremiumGatewayProtocol,
		close?: () => void
	): Promise<void> {
		draftProtocol = next;
		errorText = '';
		if (!currentCountry || !countrySupports(currentCountry, next)) return;
		await switchTo(currentCountry, next, close);
	}

	async function switchTo(
		countryCode: string,
		protocol: PremiumGatewayProtocol = draftProtocol,
		close?: () => void
	): Promise<void> {
		if (busy) return;
		busy = true;
		errorText = '';
		try {
			const result = await api.amneziaPremiumSwitch(countryCode, protocol, awgBackend);
			currentCountry = result.countryCode;
			currentProtocol = result.protocol;
			draftProtocol = result.protocol;
			close?.();
			mobileOpen = false;
			onchanged?.();
		} catch (e) {
			errorText = e instanceof Error ? e.message : 'Не удалось переключить Amnezia Premium';
		} finally {
			busy = false;
		}
	}

	function manage(close?: () => void): void {
		close?.();
		mobileOpen = false;
		onmanage();
	}
</script>

{#if visible && !loading}
	<div class="premium-quick desktop-only">
		<DropdownMenu {label} size="sm" disabled={busy}>
			{#snippet iconBefore()}
				<span class="premium-crown" aria-hidden="true">♛</span>
			{/snippet}
			{#snippet menu(close)}
				<div class="quick-menu">
					<div class="quick-section">
						<span class="quick-label">Протокол</span>
						<SegmentedControl
							value={draftProtocol}
							options={protocolOptions}
							ariaLabel="Протокол Amnezia Premium"
							disabled={busy}
							fullWidth
							onchange={(value) => void selectProtocol(value, close)}
						/>
					</div>
					<div class="quick-section quick-countries">
						<span class="quick-label">Страна</span>
						{#each countries as country (country.code)}
							<button
								type="button"
								class="quick-country"
								class:active={country.code.trim().toLowerCase() === currentCountry.trim().toLowerCase() && draftProtocol === currentProtocol}
								disabled={busy}
								onclick={() => void switchTo(country.code, draftProtocol, close)}
							>
								<span>{premiumCountryFlag(country.code)}</span>
								<span class="country-name">{country.name}</span>
								{#if country.code.trim().toLowerCase() === currentCountry.trim().toLowerCase() && draftProtocol === currentProtocol}
									<span aria-hidden="true">✓</span>
								{/if}
							</button>
						{/each}
					</div>
					{#if errorText}<p class="quick-error">{errorText}</p>{/if}
					<button type="button" class="quick-manage" onclick={() => manage(close)}>
						<Settings2 size={14} aria-hidden="true" />
						Настройки аккаунта
					</button>
				</div>
			{/snippet}
		</DropdownMenu>
	</div>

	<div class="premium-quick mobile-only">
		<Button variant="primary" size="sm" disabled={busy} onclick={() => (mobileOpen = true)}>
			{label}
			{#snippet iconAfter()}<ChevronDown size={14} aria-hidden="true" />{/snippet}
		</Button>
	</div>

	<Modal open={mobileOpen} title="Amnezia Premium" size="sm" onclose={() => (mobileOpen = false)}>
		{#snippet children()}
			<div class="mobile-sheet">
				<SegmentedControl
					value={draftProtocol}
					options={protocolOptions}
					ariaLabel="Протокол Amnezia Premium"
					disabled={busy}
					fullWidth
					onchange={(value) => void selectProtocol(value)}
				/>
				<div class="mobile-countries">
					{#each countries as country (country.code)}
						<button
							type="button"
							class="quick-country mobile-country"
							class:active={country.code.trim().toLowerCase() === currentCountry.trim().toLowerCase() && draftProtocol === currentProtocol}
							disabled={busy}
							onclick={() => void switchTo(country.code)}
						>
							<span>{premiumCountryFlag(country.code)}</span>
							<span class="country-name">{country.name}</span>
							{#if country.code.trim().toLowerCase() === currentCountry.trim().toLowerCase() && draftProtocol === currentProtocol}
								<span aria-hidden="true">✓</span>
							{/if}
						</button>
					{/each}
				</div>
				{#if errorText}<p class="quick-error">{errorText}</p>{/if}
			</div>
		{/snippet}
		{#snippet actions()}
			<Button variant="secondary" size="md" onclick={() => (mobileOpen = false)}>Закрыть</Button>
			<Button variant="primary" size="md" onclick={() => manage()}>Настройки</Button>
		{/snippet}
	</Modal>
{/if}

<style>
	.premium-quick {
		min-width: 0;
	}

	.mobile-only {
		display: none;
	}

	.quick-menu {
		width: min(340px, calc(100vw - 24px));
		display: flex;
		flex-direction: column;
		gap: 10px;
		padding: 4px;
	}

	.quick-section {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.quick-label {
		padding: 2px 4px;
		font-size: 0.6875rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--text-muted, var(--color-text-muted));
	}

	.quick-countries {
		max-height: 280px;
		overflow-y: auto;
	}

	.quick-country,
	.quick-manage {
		display: flex;
		align-items: center;
		gap: 8px;
		width: 100%;
		padding: 8px 9px;
		border: 0;
		border-radius: 7px;
		background: transparent;
		color: var(--text-primary, var(--color-text-primary));
		font: inherit;
		font-size: 0.8125rem;
		text-align: left;
		cursor: pointer;
	}

	.quick-country:hover:not(:disabled),
	.quick-manage:hover:not(:disabled) {
		background: var(--bg-hover, var(--color-bg-hover));
	}

	.quick-country.active {
		background: var(--color-accent-tint);
		color: var(--accent, var(--color-accent));
	}

	.quick-country:disabled {
		opacity: 0.55;
		cursor: wait;
	}

	.country-name {
		flex: 1;
		min-width: 0;
		overflow-wrap: anywhere;
	}

	.quick-manage {
		border-top: 1px solid var(--border, var(--color-border));
		border-radius: 0 0 7px 7px;
		color: var(--text-secondary, var(--color-text-secondary));
	}

	.quick-error {
		margin: 0;
		padding: 6px 8px;
		font-size: 0.75rem;
		line-height: 1.4;
		color: var(--error, var(--color-error));
	}

	.mobile-sheet {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.mobile-countries {
		display: flex;
		flex-direction: column;
		max-height: min(55vh, 420px);
		overflow-y: auto;
		border: 1px solid var(--border, var(--color-border));
		border-radius: 8px;
	}

	.mobile-country {
		border-radius: 0;
		border-bottom: 1px solid var(--border, var(--color-border));
		padding: 11px 10px;
		font-size: 0.875rem;
	}

	.mobile-country:last-child {
		border-bottom: 0;
	}

	@media (max-width: 640px) {
		.desktop-only {
			display: none;
		}

		.mobile-only {
			display: block;
			width: 100%;
		}

		.mobile-only :global(.btn) {
			width: 100%;
			justify-content: center;
			min-width: 0;
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
		}
	}
</style>
