import { useQuery } from '@tanstack/react-query'
import { useEffect } from 'react'
import { api } from '../api/client'
import { useDeploymentStore } from '../store/deploymentStore'

export function useDeploymentStatus() {
  const deploymentState = useDeploymentStore((s) => s.deploymentState)
  const setDeploymentState = useDeploymentStore((s) => s.setDeploymentState)

  const isActive = deploymentState === 'deploying' || deploymentState === 'destroying'

  const query = useQuery({
    queryKey: ['deploymentStatus'],
    queryFn: api.getStatus,
    refetchInterval: isActive ? 3000 : 30000,
  })

  useEffect(() => {
    if (query.data) {
      setDeploymentState(query.data.state)
    }
  }, [query.data, setDeploymentState])

  return query
}
