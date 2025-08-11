import React from 'react';
import { Routes, Route } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import CreateScanPage from './pages/CreateScanPage';   
import ScanDetailPage from './pages/ScanDetailPage';  
import ProfilePage from './pages/ProfilePage'; 
import ActivityPage from './pages/ActivityPage';  
import PrivateRoute from './auth/PrivateRoute';
import NavbarSidebar from './components/NavbarSidebar'; 
import EditScanPage from './pages/EditScanPage';
import HomePage from './pages/HomePage';




const App = () => {
  return (
    <div className="min-h-screen bg-gray-100">
      <NavbarSidebar />
      <Routes>
        <Route path="/v1/login" element={<LoginPage />} />
        <Route path="/v1/register" element={<RegisterPage />} />

        <Route path="/v1/dashboard" element={
          <PrivateRoute>
            <DashboardPage />
          </PrivateRoute>
        } />
        <Route path="/" element={<HomePage />} />
        <Route path="/v1/create-scan" element={
          <PrivateRoute>
            <CreateScanPage />
          </PrivateRoute>
        } />
        <Route path="/v1/scan/:id" element={
          <PrivateRoute>
            <ScanDetailPage />
          </PrivateRoute>
        } />
        <Route path="/v1/profile/:id" element={
          <PrivateRoute>
            <ProfilePage />
          </PrivateRoute>
        } />
        <Route path="/v1/edit-scan/:id" element={
          <PrivateRoute>
            <EditScanPage />
          </PrivateRoute>
        } />
        <Route path="/v1/activity" element={
          <PrivateRoute>
            <ActivityPage />
          </PrivateRoute>
        } />
      </Routes>
    </div>
  );
};



export default App;
