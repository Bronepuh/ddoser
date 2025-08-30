import { Layout, Menu } from 'antd';
import { SecurityScanTwoTone } from '@ant-design/icons';

const { Header: AntHeader } = Layout;

export default function Header() {
  return (
    <AntHeader style={{ display: 'flex', alignItems: 'center' }}>
      <div style={{ color: 'white', fontWeight: 'bold', marginRight: 24 }}>
        <SecurityScanTwoTone twoToneColor="#1677ff" /> AuditTool
      </div>
      <Menu
        theme="dark"
        mode="horizontal"
        items={[
          { key: 'home', label: 'Главная' },
          { key: 'about', label: 'О проекте' },
        ]}
      />
    </AntHeader>
  );
}
