interface ErrorAlertProps {
  title?: string
  message: string
}

export function ErrorAlert({ title = 'Something went wrong', message }: ErrorAlertProps) {
  return (
    <div className="border-l-2 border-critical bg-critical/10 px-4 py-3 text-sm text-rose-100">
      <p className="font-semibold">{title}</p>
      <p className="mt-1 text-rose-100/90">{message}</p>
    </div>
  )
}
