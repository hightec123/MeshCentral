import { expect, test } from '@playwright/test';

test('real server serves the console and truthfully reports unavailable enrollment', async ({ page, request }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Devices', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'No devices connected yet' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'What’s available in this preview?' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText('Agent enrollment');
  await expect(dialog).toContainText('Not available yet');
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();

  const enrollment = await request.get('/agent.ashx');
  expect(enrollment.status()).toBe(503);
  expect((await enrollment.json()).code).toBe('agent_enrollment_unavailable');
  const capabilities = await request.get('/api/v1/server');
  expect((await capabilities.json()).capabilities.agent_enrollment).toBe(false);
  expect(errors).toEqual([]);
});

test('connection failure is recoverable without reloading the page', async ({ page }) => {
  await page.route('**/api/**', (route) => route.abort('failed'));
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('Device list unavailable.');
  await expect(page.getByRole('heading', { name: 'No devices connected yet' })).not.toBeVisible();
  await page.unroute('**/api/**');
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'No devices connected yet' })).toBeVisible();
  await expect(page.getByRole('alert')).not.toBeVisible();
});

test('search and filters work with an explicitly injected test inventory', async ({ page }) => {
  // Test-only data. The real server never seeds or fabricates online devices.
  await page.route('**/api/v1/devices', (route) => route.fulfill({ json: { devices: [
    { id: 'test-1', name: 'Lab laptop', group: 'Lab', platform: 'Windows', status: 'online', last_seen: '2026-11-03T23:00:00Z' },
    { id: 'test-2', name: 'Test workstation', group: 'Testing', platform: 'Linux', status: 'offline', last_seen: null },
  ] } }));
  await page.goto('/');
  await expect(page.getByRole('cell', { name: 'Lab laptop', exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: 'Connection status' }).selectOption('offline');
  await expect(page.getByRole('cell', { name: 'Test workstation', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Lab laptop', exact: true })).not.toBeVisible();
  await page.getByRole('combobox', { name: 'Platform', exact: true }).selectOption('Windows');
  await expect(page.getByRole('heading', { name: 'No matching devices' })).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await page.getByRole('searchbox', { name: 'Search devices' }).fill('Testing');
  await expect(page.getByRole('cell', { name: 'Test workstation', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Lab laptop', exact: true })).not.toBeVisible();
});

test('a failed refresh marks retained inventory as out of date', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'No devices connected yet' })).toBeVisible();
  await page.route('**/api/v1/devices', (route) => route.fulfill({ status: 503, json: { code: 'unavailable' } }));
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Device information may be out of date.');
  await expect(page.getByText(/Last successful update/)).toBeVisible();
});

test('invalid inventory cannot be presented as a connected device', async ({ page }) => {
  await page.route('**/api/v1/devices', (route) => route.fulfill({ json: {
    devices: [{ name: 'Unverified device', status: 'online' }],
  } }));
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('The server sent unexpected device information.');
  await expect(page.getByRole('cell', { name: 'Unverified device' })).not.toBeVisible();
  await expect(page.getByRole('heading', { name: 'No devices connected yet' })).not.toBeVisible();
});

test('layout stays within the viewport and keyboard can reach the controls', async ({ page }, testInfo) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'No devices connected yet' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to devices' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('main')).toBeFocused();
  await page.evaluate(() => { if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); });
  await page.screenshot({ path: testInfo.outputPath('console.png'), fullPage: true });
});
