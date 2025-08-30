// src/App.tsx

import { App as AntdApp } from 'antd';
import HomePage from './pages/home-page/HomePage';
import MainLayout from '@shared/ui/layout/MainLayout';
import './App.css'; // стили фона

export default function App() {
  return (
    <AntdApp>
      <MainLayout>
        <HomePage />
      </MainLayout>
    </AntdApp>
  );
}
