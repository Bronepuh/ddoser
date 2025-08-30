import React from 'react';
import { Layout, Space, Typography } from 'antd';
import styles from './MainLayout.module.scss';

const { Header, Content, Footer } = Layout;

export default function MainLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Layout className={styles.layout}>
      <Header className={styles.header}>
        <Space className={styles.headerInner}>
          <Typography.Title level={3} className={styles.logo}>
            DDOSER
          </Typography.Title>
        </Space>
      </Header>

      <Content className={styles.content}>{children}</Content>

      <Footer className={styles.footer}>
        © 2025 bronepuh services | <a href="https://bronepuh.ru">bronepuh.ru</a>
      </Footer>
    </Layout>
  );
}
