import ReadinessIndicator from './ReadinessIndicator'
import ReceiptFeed from './ReceiptFeed'
import ApprovalInbox from './ApprovalInbox'

interface Props { onSetupAgain: () => void }

export default function Dashboard({ onSetupAgain }: Props) {
  return (
    <div style={{ maxWidth: 800, margin: '0 auto', padding: '40px 24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
        <h1 style={{ fontSize: 24, fontWeight: 700, margin: 0 }}>Keylatch</h1>
        <ReadinessIndicator onSetupAgain={onSetupAgain} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        <div>
          <h3 style={{ marginBottom: 16 }}>Recent Activity</h3>
          <ReceiptFeed />
        </div>
        <div>
          <h3 style={{ marginBottom: 16 }}>Pending Approvals</h3>
          <ApprovalInbox />
        </div>
      </div>
    </div>
  )
}
