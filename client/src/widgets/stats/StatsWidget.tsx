// src/widgets/StatsWidget.tsx
import React, { useEffect, useState } from 'react';
import { EyeOutlined, UserOutlined } from '@ant-design/icons';
import socket from '@shared/sockets/socket';

interface Stats {
  views: number;
  uniqueUsers: number;
}

const StatsWidget: React.FC = () => {
  const [stats, setStats] = useState<Stats>({ views: 0, uniqueUsers: 0 });

  useEffect(() => {
    const handleStats = (data: Stats) => setStats(data);

    socket.on('stats', handleStats);

    return () => {
      socket.off('stats', handleStats);
    };
  }, []);

  return (
    <div
      style={{
        position: 'absolute',
        top: 5,
        right: 10,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderRadius: 8,
        padding: '0 5px',
        height: 30,
        width: 80,
        boxShadow: '0 2px 6px rgba(0,0,0,0.15)',
        fontSize: 14,
        color: 'white',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <EyeOutlined style={{ fontSize: 18, color: '#1890ff' }} />
        <span>{stats.views}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <UserOutlined style={{ fontSize: 18, color: '#52c41a' }} />
        <span>{stats.uniqueUsers}</span>
      </div>
    </div>
  );
};

export default StatsWidget;
