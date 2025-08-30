import { Layout, Space, Typography } from 'antd';

const { Footer: AntFooter } = Layout;

export default function Footer() {
  return (
    <AntFooter style={{ textAlign: 'center' }}>
      <Space direction="vertical" size={2}>
        <Typography.Text>© 2025, Автор: Иван Иванов</Typography.Text>
        <Typography.Text type="secondary">
          Telegram: @my_nick | Email: me@example.com
        </Typography.Text>
      </Space>
    </AntFooter>
  );
}
