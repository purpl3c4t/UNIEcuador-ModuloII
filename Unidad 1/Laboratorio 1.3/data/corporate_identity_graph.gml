graph [
  directed 1
  node [
    id 0
    label "User_Carlos_Finanzas"
    type "User"
    tier 3
    ip "10.0.10.15"
  ]
  node [
    id 1
    label "Host_WS_Finanzas"
    type "Endpoint"
    tier 3
    ip "10.0.10.15"
  ]
  node [
    id 2
    label "Host_WS_Dev"
    type "Endpoint"
    tier 3
    ip "10.0.20.45"
  ]
  node [
    id 3
    label "Srv_Jumpbox_Admin"
    type "Server"
    tier 2
    ip "10.0.1.5"
  ]
  node [
    id 4
    label "User_Svc_Backup"
    type "ServiceAccount"
    tier 1
    ip "10.0.1.50"
  ]
  node [
    id 5
    label "Srv_Database_Prod"
    type "Database"
    tier 1
    ip "10.0.2.100"
  ]
  node [
    id 6
    label "DC_Primary_Core"
    type "DomainController"
    tier 0
    ip "10.0.0.1"
  ]
  edge [
    source 0
    target 1
    probability 0.98
    weight 0.020202707317519466
  ]
  edge [
    source 1
    target 2
    probability 0.001
    weight 6.907755278982137
  ]
  edge [
    source 1
    target 3
    probability 0.005
    weight 5.298317366548036
  ]
  edge [
    source 2
    target 3
    probability 0.05
    weight 2.995732273553991
  ]
  edge [
    source 3
    target 4
    probability 0.85
    weight 0.16251892949777494
  ]
  edge [
    source 3
    target 6
    probability 0.7
    weight 0.35667494393873245
  ]
  edge [
    source 4
    target 5
    probability 0.9
    weight 0.10536051565782628
  ]
]
