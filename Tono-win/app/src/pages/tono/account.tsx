import { useTranslation } from 'react-i18next'

import { TonoAccountCard } from '@/tono-ui/TonoAccountCard'

const AccountPage = () => {
  const { t } = useTranslation()

  return (
    <div className="tono-page">
      <h1
        className="tono-page-title"
        style={{ marginBottom: 18 }}
      >
        {t('tono.account.title')}
      </h1>
      <div style={{ maxWidth: 520 }}>
        <TonoAccountCard />
      </div>
    </div>
  )
}

export default AccountPage
