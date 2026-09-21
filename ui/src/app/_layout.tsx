// The shell. A Stack and a dark theme, and NOTHING ELSE: no auth provider, no
// account gate, no analytics. The box this page came from is the identity --
// komizo ui binds loopback or the tailnet interface, and being able to open
// the page is being allowed to see it.

import { DarkTheme, Stack, ThemeProvider } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import React from 'react';

export default function Layout() {
  return (
    <ThemeProvider value={DarkTheme}>
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: '#0c1116' },
          headerTintColor: '#e6edf3',
          contentStyle: { backgroundColor: '#0c1116' },
        }}>
        <Stack.Screen name="index" options={{ title: 'komizo' }} />
        <Stack.Screen name="app/[name]" options={{ title: 'app' }} />
      </Stack>
    </ThemeProvider>
  );
}
