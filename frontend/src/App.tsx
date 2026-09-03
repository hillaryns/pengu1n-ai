import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from './components/AppLayout'
import { ApiConfigProvider } from './context/ApiConfigContext'
import { DashboardPage } from './pages/DashboardPage'
import { NewScanPage } from './pages/NewScanPage'
import { ReportPage } from './pages/ReportPage'
import { ScanDetailPage } from './pages/ScanDetailPage'
import { ScanHistoryPage } from './pages/ScanHistoryPage'
import { SettingsPage } from './pages/SettingsPage'

export default function App() {
  return (
    <ApiConfigProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<AppLayout />}>
            <Route index element={<DashboardPage />} />
            <Route path="scans" element={<ScanHistoryPage />} />
            <Route path="scans/new" element={<NewScanPage />} />
            <Route path="scans/:scanId" element={<ScanDetailPage />} />
            <Route path="scans/:scanId/report" element={<ReportPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ApiConfigProvider>
  )
}
