/*
Copyright © 2021 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package model

import "fmt"

type BPFCmd uint32

const (
	BpfMapCreate BPFCmd = iota
	BpfCmdMapLookupElem
	BpfCmdMapUpdateElem
	BpfCmdMapDeleteElem
	BpfCmdMapGetNextKey
	BpfProgLoad
	BpfObjPin
	BpfObjGet
	BpfProgAttach
	BpfProgDetach
	BpfProgTestRun
	BpfProgGetNextId
	BpfMapGetNextId
	BpfProgGetFdById
	BpfMapGetFdById
	BpfObjGetInfoByFd
	BpfProgQuery
	BpfRawTracepointOpen
	BpfBtfLoad
	BpfBtfGetFdById
	BpfTaskFdQuery
	BpfMapLookupAndDeleteElem
	BpfMapFreeze
	BpfBtfGetNextId
	BpfMapLookupBatch
	BpfMapLookupAndDeleteBatch
	BpfMapUpdateBatch
	BpfMapDeleteBatch
	BpfLinkCreate
	BpfLinkUpdate
	BpfLinkGetFdById
	BpfLinkGetNextId
	BpfEnableStats
	BpfIterCreate
	BpfLinkDetach
	BpfProgBindMap
)

func (cmd BPFCmd) MarshalJSON() ([]byte, error) {
	return []byte(`"` + cmd.String() + `"`), nil
}

func (cmd BPFCmd) String() string {
	switch cmd {
	case BpfMapCreate:
		return "BpfMapCreate"
	case BpfCmdMapLookupElem:
		return "BpfMapLookupElem"
	case BpfCmdMapUpdateElem:
		return "BpfMapUpdateElem"
	case BpfCmdMapDeleteElem:
		return "BpfMapDeleteElem"
	case BpfCmdMapGetNextKey:
		return "BpfMapGetNextKey"
	case BpfProgLoad:
		return "BpfProgLoad"
	case BpfObjPin:
		return "BpfObjPin"
	case BpfObjGet:
		return "BpfObjGet"
	case BpfProgAttach:
		return "BpfProgAttach"
	case BpfProgDetach:
		return "BpfProgDetach"
	case BpfProgTestRun:
		return "BpfProgTestRun"
	case BpfProgGetNextId:
		return "BpfProgGetNextId"
	case BpfMapGetNextId:
		return "BpfMapGetNextId"
	case BpfProgGetFdById:
		return "BpfProgGetFdById"
	case BpfMapGetFdById:
		return "BpfMapGetFdById"
	case BpfObjGetInfoByFd:
		return "BpfObjGetInfoByFd"
	case BpfProgQuery:
		return "BpfProgQuery"
	case BpfRawTracepointOpen:
		return "BpfRawTracepointOpen"
	case BpfBtfLoad:
		return "BpfBtfLoad"
	case BpfBtfGetFdById:
		return "BpfBtfGetFdById"
	case BpfTaskFdQuery:
		return "BpfTaskFdQuery"
	case BpfMapLookupAndDeleteElem:
		return "BpfMapLookupAndDeleteElem"
	case BpfMapFreeze:
		return "BpfMapFreeze"
	case BpfBtfGetNextId:
		return "BpfBtfGetNextId"
	case BpfMapLookupBatch:
		return "BpfMapLookupBatch"
	case BpfMapLookupAndDeleteBatch:
		return "BpfMapLookupAndDeleteBatch"
	case BpfMapUpdateBatch:
		return "BpfMapUpdateBatch"
	case BpfMapDeleteBatch:
		return "BpfMapDeleteBatch"
	case BpfLinkCreate:
		return "BpfLinkCreate"
	case BpfLinkUpdate:
		return "BpfLinkUpdate"
	case BpfLinkGetFdById:
		return "BpfLinkGetFdById"
	case BpfLinkGetNextId:
		return "BpfLinkGetNextId"
	case BpfEnableStats:
		return "BpfEnableStats"
	case BpfIterCreate:
		return "BpfIterCreate"
	case BpfLinkDetach:
		return "BpfLinkDetach"
	case BpfProgBindMap:
		return "BpfProgBindMap"
	}
	return fmt.Sprintf("BPFCmd(%d)", cmd)
}

type HelperFunc uint32

const (
	BpfUnspec HelperFunc = iota
	BpfMapLookupElem
	BpfMapUpdateElem
	BpfMapDeleteElem
	BpfProbeRead
	BpfKtimeGetNs
	BpfTracePrintk
	BpfGetPrandomU32
	BpfGetSmpProcessorId
	BpfSkbStoreBytes
	BpfL3CsumReplace
	BpfL4CsumReplace
	BpfTailCall
	BpfCloneRedirect
	BpfGetCurrentPidTgid
	BpfGetCurrentUidGid
	BpfGetCurrentComm
	BpfGetCgroupClassid
	BpfSkbVlanPush
	BpfSkbVlanPop
	BpfSkbGetTunnelKey
	BpfSkbSetTunnelKey
	BpfPerfEventRead
	BpfRedirect
	BpfGetRouteRealm
	BpfPerfEventOutput
	BpfSkbLoadBytes
	BpfGetStackid
	BpfCsumDiff
	BpfSkbGetTunnelOpt
	BpfSkbSetTunnelOpt
	BpfSkbChangeProto
	BpfSkbChangeType
	BpfSkbUnderCgroup
	BpfGetHashRecalc
	BpfGetCurrentTask
	BpfProbeWriteUser
	BpfCurrentTaskUnderCgroup
	BpfSkbChangeTail
	BpfSkbPullData
	BpfCsumUpdate
	BpfSetHashInvalid
	BpfGetNumaNodeId
	BpfSkbChangeHead
	BpfXdpAdjustHead
	BpfProbeReadStr
	BpfGetSocketCookie
	BpfGetSocketUid
	BpfSetHash
	BpfSetsockopt
	BpfSkbAdjustRoom
	BpfRedirectMap
	BpfSkRedirectMap
	BpfSockMapUpdate
	BpfXdpAdjustMeta
	BpfPerfEventReadValue
	BpfPerfProgReadValue
	BpfGetsockopt
	BpfOverrideReturn
	BpfSockOpsCbFlagsSet
	BpfMsgRedirectMap
	BpfMsgApplyBytes
	BpfMsgCorkBytes
	BpfMsgPullData
	BpfBind
	BpfXdpAdjustTail
	BpfSkbGetXfrmState
	BpfGetStack
	BpfSkbLoadBytesRelative
	BpfFibLookup
	BpfSockHashUpdate
	BpfMsgRedirectHash
	BpfSkRedirectHash
	BpfLwtPushEncap
	BpfLwtSeg6StoreBytes
	BpfLwtSeg6AdjustSrh
	BpfLwtSeg6Action
	BpfRcRepeat
	BpfRcKeydown
	BpfSkbCgroupId
	BpfGetCurrentCgroupId
	BpfGetLocalStorage
	BpfSkSelectReuseport
	BpfSkbAncestorCgroupId
	BpfSkLookupTcp
	BpfSkLookupUdp
	BpfSkRelease
	BpfMapPushElem
	BpfMapPopElem
	BpfMapPeekElem
	BpfMsgPushData
	BpfMsgPopData
	BpfRcPointerRel
	BpfSpinLock
	BpfSpinUnlock
	BpfSkFullsock
	BpfTcpSock
	BpfSkbEcnSetCe
	BpfGetListenerSock
	BpfSkcLookupTcp
	BpfTcpCheckSyncookie
	BpfSysctlGetName
	BpfSysctlGetCurrentValue
	BpfSysctlGetNewValue
	BpfSysctlSetNewValue
	BpfStrtol
	BpfStrtoul
	BpfSkStorageGet
	BpfSkStorageDelete
	BpfSendSignal
	BpfTcpGenSyncookie
	BpfSkbOutput
	BpfProbeReadUser
	BpfProbeReadKernel
	BpfProbeReadUserStr
	BpfProbeReadKernelStr
	BpfTcpSendAck
	BpfSendSignalThread
	BpfJiffies64
	BpfReadBranchRecords
	BpfGetNsCurrentPidTgid
	BpfXdpOutput
	BpfGetNetnsCookie
	BpfGetCurrentAncestorCgroupId
	BpfSkAssign
	BpfKtimeGetBootNs
	BpfSeqPrintf
	BpfSeqWrite
	BpfSkCgroupId
	BpfSkAncestorCgroupId
	BpfRingbufOutput
	BpfRingbufReserve
	BpfRingbufSubmit
	BpfRingbufDiscard
	BpfRingbufQuery
	BpfCsumLevel
	BpfSkcToTcp6Sock
	BpfSkcToTcpSock
	BpfSkcToTcpTimewaitSock
	BpfSkcToTcpRequestSock
	BpfSkcToUdp6Sock
	BpfGetTaskStack
	BpfLoadHdrOpt
	BpfStoreHdrOpt
	BpfReserveHdrOpt
	BpfInodeStorageGet
	BpfInodeStorageDelete
	BpfDPath
	BpfCopyFromUser
	BpfSnprintfBtf
	BpfSeqPrintfBtf
	BpfSkbCgroupClassid
	BpfRedirectNeigh
	BpfPerCpuPtr
	BpfThisCpuPtr
	BpfRedirectPeer
	BpfTaskStorageGet
	BpfTaskStorageDelete
	BpfGetCurrentTaskBtf
	BpfBprmOptsSet
	BpfKtimeGetCoarseNs
	BpfImaInodeHash
	BpfSockFromFile
	BpfCheckMtu
	BpfForEachMapElem
	BpfSnprintf
)

func (f HelperFunc) MarshalJSON() ([]byte, error) {
	return []byte(`"` + f.String() + `"`), nil
}

func (f HelperFunc) String() string {
	switch f {
	case BpfUnspec:
		return "BpfUnspec"
	case BpfMapLookupElem:
		return "BpfMapLookupElem"
	case BpfMapUpdateElem:
		return "BpfMapUpdateElem"
	case BpfMapDeleteElem:
		return "BpfMapDeleteElem"
	case BpfProbeRead:
		return "BpfProbeRead"
	case BpfKtimeGetNs:
		return "BpfKtimeGetNs"
	case BpfTracePrintk:
		return "BpfTracePrintk"
	case BpfGetPrandomU32:
		return "BpfGetPrandomU32"
	case BpfGetSmpProcessorId:
		return "BpfGetSmpProcessorId"
	case BpfSkbStoreBytes:
		return "BpfSkbStoreBytes"
	case BpfL3CsumReplace:
		return "BpfL3CsumReplace"
	case BpfL4CsumReplace:
		return "BpfL4CsumReplace"
	case BpfTailCall:
		return "BpfTailCall"
	case BpfCloneRedirect:
		return "BpfCloneRedirect"
	case BpfGetCurrentPidTgid:
		return "BpfGetCurrentPidTgid"
	case BpfGetCurrentUidGid:
		return "BpfGetCurrentUidGid"
	case BpfGetCurrentComm:
		return "BpfGetCurrentComm"
	case BpfGetCgroupClassid:
		return "BpfGetCgroupClassid"
	case BpfSkbVlanPush:
		return "BpfSkbVlanPush"
	case BpfSkbVlanPop:
		return "BpfSkbVlanPop"
	case BpfSkbGetTunnelKey:
		return "BpfSkbGetTunnelKey"
	case BpfSkbSetTunnelKey:
		return "BpfSkbSetTunnelKey"
	case BpfPerfEventRead:
		return "BpfPerfEventRead"
	case BpfRedirect:
		return "BpfRedirect"
	case BpfGetRouteRealm:
		return "BpfGetRouteRealm"
	case BpfPerfEventOutput:
		return "BpfPerfEventOutput"
	case BpfSkbLoadBytes:
		return "BpfSkbLoadBytes"
	case BpfGetStackid:
		return "BpfGetStackid"
	case BpfCsumDiff:
		return "BpfCsumDiff"
	case BpfSkbGetTunnelOpt:
		return "BpfSkbGetTunnelOpt"
	case BpfSkbSetTunnelOpt:
		return "BpfSkbSetTunnelOpt"
	case BpfSkbChangeProto:
		return "BpfSkbChangeProto"
	case BpfSkbChangeType:
		return "BpfSkbChangeType"
	case BpfSkbUnderCgroup:
		return "BpfSkbUnderCgroup"
	case BpfGetHashRecalc:
		return "BpfGetHashRecalc"
	case BpfGetCurrentTask:
		return "BpfGetCurrentTask"
	case BpfProbeWriteUser:
		return "BpfProbeWriteUser"
	case BpfCurrentTaskUnderCgroup:
		return "BpfCurrentTaskUnderCgroup"
	case BpfSkbChangeTail:
		return "BpfSkbChangeTail"
	case BpfSkbPullData:
		return "BpfSkbPullData"
	case BpfCsumUpdate:
		return "BpfCsumUpdate"
	case BpfSetHashInvalid:
		return "BpfSetHashInvalid"
	case BpfGetNumaNodeId:
		return "BpfGetNumaNodeId"
	case BpfSkbChangeHead:
		return "BpfSkbChangeHead"
	case BpfXdpAdjustHead:
		return "BpfXdpAdjustHead"
	case BpfProbeReadStr:
		return "BpfProbeReadStr"
	case BpfGetSocketCookie:
		return "BpfGetSocketCookie"
	case BpfGetSocketUid:
		return "BpfGetSocketUid"
	case BpfSetHash:
		return "BpfSetHash"
	case BpfSetsockopt:
		return "BpfSetsockopt"
	case BpfSkbAdjustRoom:
		return "BpfSkbAdjustRoom"
	case BpfRedirectMap:
		return "BpfRedirectMap"
	case BpfSkRedirectMap:
		return "BpfSkRedirectMap"
	case BpfSockMapUpdate:
		return "BpfSockMapUpdate"
	case BpfXdpAdjustMeta:
		return "BpfXdpAdjustMeta"
	case BpfPerfEventReadValue:
		return "BpfPerfEventReadValue"
	case BpfPerfProgReadValue:
		return "BpfPerfProgReadValue"
	case BpfGetsockopt:
		return "BpfGetsockopt"
	case BpfOverrideReturn:
		return "BpfOverrideReturn"
	case BpfSockOpsCbFlagsSet:
		return "BpfSockOpsCbFlagsSet"
	case BpfMsgRedirectMap:
		return "BpfMsgRedirectMap"
	case BpfMsgApplyBytes:
		return "BpfMsgApplyBytes"
	case BpfMsgCorkBytes:
		return "BpfMsgCorkBytes"
	case BpfMsgPullData:
		return "BpfMsgPullData"
	case BpfBind:
		return "BpfBind"
	case BpfXdpAdjustTail:
		return "BpfXdpAdjustTail"
	case BpfSkbGetXfrmState:
		return "BpfSkbGetXfrmState"
	case BpfGetStack:
		return "BpfGetStack"
	case BpfSkbLoadBytesRelative:
		return "BpfSkbLoadBytesRelative"
	case BpfFibLookup:
		return "BpfFibLookup"
	case BpfSockHashUpdate:
		return "BpfSockHashUpdate"
	case BpfMsgRedirectHash:
		return "BpfMsgRedirectHash"
	case BpfSkRedirectHash:
		return "BpfSkRedirectHash"
	case BpfLwtPushEncap:
		return "BpfLwtPushEncap"
	case BpfLwtSeg6StoreBytes:
		return "BpfLwtSeg6StoreBytes"
	case BpfLwtSeg6AdjustSrh:
		return "BpfLwtSeg6AdjustSrh"
	case BpfLwtSeg6Action:
		return "BpfLwtSeg6Action"
	case BpfRcRepeat:
		return "BpfRcRepeat"
	case BpfRcKeydown:
		return "BpfRcKeydown"
	case BpfSkbCgroupId:
		return "BpfSkbCgroupId"
	case BpfGetCurrentCgroupId:
		return "BpfGetCurrentCgroupId"
	case BpfGetLocalStorage:
		return "BpfGetLocalStorage"
	case BpfSkSelectReuseport:
		return "BpfSkSelectReuseport"
	case BpfSkbAncestorCgroupId:
		return "BpfSkbAncestorCgroupId"
	case BpfSkLookupTcp:
		return "BpfSkLookupTcp"
	case BpfSkLookupUdp:
		return "BpfSkLookupUdp"
	case BpfSkRelease:
		return "BpfSkRelease"
	case BpfMapPushElem:
		return "BpfMapPushElem"
	case BpfMapPopElem:
		return "BpfMapPopElem"
	case BpfMapPeekElem:
		return "BpfMapPeekElem"
	case BpfMsgPushData:
		return "BpfMsgPushData"
	case BpfMsgPopData:
		return "BpfMsgPopData"
	case BpfRcPointerRel:
		return "BpfRcPointerRel"
	case BpfSpinLock:
		return "BpfSpinLock"
	case BpfSpinUnlock:
		return "BpfSpinUnlock"
	case BpfSkFullsock:
		return "BpfSkFullsock"
	case BpfTcpSock:
		return "BpfTcpSock"
	case BpfSkbEcnSetCe:
		return "BpfSkbEcnSetCe"
	case BpfGetListenerSock:
		return "BpfGetListenerSock"
	case BpfSkcLookupTcp:
		return "BpfSkcLookupTcp"
	case BpfTcpCheckSyncookie:
		return "BpfTcpCheckSyncookie"
	case BpfSysctlGetName:
		return "BpfSysctlGetName"
	case BpfSysctlGetCurrentValue:
		return "BpfSysctlGetCurrentValue"
	case BpfSysctlGetNewValue:
		return "BpfSysctlGetNewValue"
	case BpfSysctlSetNewValue:
		return "BpfSysctlSetNewValue"
	case BpfStrtol:
		return "BpfStrtol"
	case BpfStrtoul:
		return "BpfStrtoul"
	case BpfSkStorageGet:
		return "BpfSkStorageGet"
	case BpfSkStorageDelete:
		return "BpfSkStorageDelete"
	case BpfSendSignal:
		return "BpfSendSignal"
	case BpfTcpGenSyncookie:
		return "BpfTcpGenSyncookie"
	case BpfSkbOutput:
		return "BpfSkbOutput"
	case BpfProbeReadUser:
		return "BpfProbeReadUser"
	case BpfProbeReadKernel:
		return "BpfProbeReadKernel"
	case BpfProbeReadUserStr:
		return "BpfProbeReadUserStr"
	case BpfProbeReadKernelStr:
		return "BpfProbeReadKernelStr"
	case BpfTcpSendAck:
		return "BpfTcpSendAck"
	case BpfSendSignalThread:
		return "BpfSendSignalThread"
	case BpfJiffies64:
		return "BpfJiffies64"
	case BpfReadBranchRecords:
		return "BpfReadBranchRecords"
	case BpfGetNsCurrentPidTgid:
		return "BpfGetNsCurrentPidTgid"
	case BpfXdpOutput:
		return "BpfXdpOutput"
	case BpfGetNetnsCookie:
		return "BpfGetNetnsCookie"
	case BpfGetCurrentAncestorCgroupId:
		return "BpfGetCurrentAncestorCgroupId"
	case BpfSkAssign:
		return "BpfSkAssign"
	case BpfKtimeGetBootNs:
		return "BpfKtimeGetBootNs"
	case BpfSeqPrintf:
		return "BpfSeqPrintf"
	case BpfSeqWrite:
		return "BpfSeqWrite"
	case BpfSkCgroupId:
		return "BpfSkCgroupId"
	case BpfSkAncestorCgroupId:
		return "BpfSkAncestorCgroupId"
	case BpfRingbufOutput:
		return "BpfRingbufOutput"
	case BpfRingbufReserve:
		return "BpfRingbufReserve"
	case BpfRingbufSubmit:
		return "BpfRingbufSubmit"
	case BpfRingbufDiscard:
		return "BpfRingbufDiscard"
	case BpfRingbufQuery:
		return "BpfRingbufQuery"
	case BpfCsumLevel:
		return "BpfCsumLevel"
	case BpfSkcToTcp6Sock:
		return "BpfSkcToTcp6Sock"
	case BpfSkcToTcpSock:
		return "BpfSkcToTcpSock"
	case BpfSkcToTcpTimewaitSock:
		return "BpfSkcToTcpTimewaitSock"
	case BpfSkcToTcpRequestSock:
		return "BpfSkcToTcpRequestSock"
	case BpfSkcToUdp6Sock:
		return "BpfSkcToUdp6Sock"
	case BpfGetTaskStack:
		return "BpfGetTaskStack"
	case BpfLoadHdrOpt:
		return "BpfLoadHdrOpt"
	case BpfStoreHdrOpt:
		return "BpfStoreHdrOpt"
	case BpfReserveHdrOpt:
		return "BpfReserveHdrOpt"
	case BpfInodeStorageGet:
		return "BpfInodeStorageGet"
	case BpfInodeStorageDelete:
		return "BpfInodeStorageDelete"
	case BpfDPath:
		return "BpfDPath"
	case BpfCopyFromUser:
		return "BpfCopyFromUser"
	case BpfSnprintfBtf:
		return "BpfSnprintfBtf"
	case BpfSeqPrintfBtf:
		return "BpfSeqPrintfBtf"
	case BpfSkbCgroupClassid:
		return "BpfSkbCgroupClassid"
	case BpfRedirectNeigh:
		return "BpfRedirectNeigh"
	case BpfPerCpuPtr:
		return "BpfPerCpuPtr"
	case BpfThisCpuPtr:
		return "BpfThisCpuPtr"
	case BpfRedirectPeer:
		return "BpfRedirectPeer"
	case BpfTaskStorageGet:
		return "BpfTaskStorageGet"
	case BpfTaskStorageDelete:
		return "BpfTaskStorageDelete"
	case BpfGetCurrentTaskBtf:
		return "BpfGetCurrentTaskBtf"
	case BpfBprmOptsSet:
		return "BpfBprmOptsSet"
	case BpfKtimeGetCoarseNs:
		return "BpfKtimeGetCoarseNs"
	case BpfImaInodeHash:
		return "BpfImaInodeHash"
	case BpfSockFromFile:
		return "BpfSockFromFile"
	case BpfCheckMtu:
		return "BpfCheckMtu"
	case BpfForEachMapElem:
		return "BpfForEachMapElem"
	case BpfSnprintf:
		return "BpfSnprintf"
	}
	return fmt.Sprintf("HelperFunc(%d)", f)
}

type MapType uint32

const (
	BpfMapTypeUnspec MapType = iota
	BpfMapTypeHash
	BpfMapTypeArray
	BpfMapTypeProgArray
	BpfMapTypePerfEventArray
	BpfMapTypePercpuHash
	BpfMapTypePercpuArray
	BpfMapTypeStackTrace
	BpfMapTypeCgroupArray
	BpfMapTypeLruHash
	BpfMapTypeLruPercpuHash
	BpfMapTypeLpmTrie
	BpfMapTypeArrayOfMaps
	BpfMapTypeHashOfMaps
	BpfMapTypeDevmap
	BpfMapTypeSockmap
	BpfMapTypeCpumap
	BpfMapTypeXskmap
	BpfMapTypeSockhash
	BpfMapTypeCgroupStorage
	BpfMapTypeReuseportSockarray
	BpfMapTypePercpuCgroupStorage
	BpfMapTypeQueue
	BpfMapTypeStack
	BpfMapTypeSkStorage
	BpfMapTypeDevmapHash
	BpfMapTypeStructOps
	BpfMapTypeRingbuf
	BpfMapTypeInodeStorage
	BpfMapTypeTaskStorage
)

func (m MapType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + m.String() + `"`), nil
}

func (m MapType) String() string {
	switch m {
	case BpfMapTypeUnspec:
		return "BpfMapTypeUnspec"
	case BpfMapTypeHash:
		return "BpfMapTypeHash"
	case BpfMapTypeArray:
		return "BpfMapTypeArray"
	case BpfMapTypeProgArray:
		return "BpfMapTypeProgArray"
	case BpfMapTypePerfEventArray:
		return "BpfMapTypePerfEventArray"
	case BpfMapTypePercpuHash:
		return "BpfMapTypePercpuHash"
	case BpfMapTypePercpuArray:
		return "BpfMapTypePercpuArray"
	case BpfMapTypeStackTrace:
		return "BpfMapTypeStackTrace"
	case BpfMapTypeCgroupArray:
		return "BpfMapTypeCgroupArray"
	case BpfMapTypeLruHash:
		return "BpfMapTypeLruHash"
	case BpfMapTypeLruPercpuHash:
		return "BpfMapTypeLruPercpuHash"
	case BpfMapTypeLpmTrie:
		return "BpfMapTypeLpmTrie"
	case BpfMapTypeArrayOfMaps:
		return "BpfMapTypeArrayOfMaps"
	case BpfMapTypeHashOfMaps:
		return "BpfMapTypeHashOfMaps"
	case BpfMapTypeDevmap:
		return "BpfMapTypeDevmap"
	case BpfMapTypeSockmap:
		return "BpfMapTypeSockmap"
	case BpfMapTypeCpumap:
		return "BpfMapTypeCpumap"
	case BpfMapTypeXskmap:
		return "BpfMapTypeXskmap"
	case BpfMapTypeSockhash:
		return "BpfMapTypeSockhash"
	case BpfMapTypeCgroupStorage:
		return "BpfMapTypeCgroupStorage"
	case BpfMapTypeReuseportSockarray:
		return "BpfMapTypeReuseportSockarray"
	case BpfMapTypePercpuCgroupStorage:
		return "BpfMapTypePercpuCgroupStorage"
	case BpfMapTypeQueue:
		return "BpfMapTypeQueue"
	case BpfMapTypeStack:
		return "BpfMapTypeStack"
	case BpfMapTypeSkStorage:
		return "BpfMapTypeSkStorage"
	case BpfMapTypeDevmapHash:
		return "BpfMapTypeDevmapHash"
	case BpfMapTypeStructOps:
		return "BpfMapTypeStructOps"
	case BpfMapTypeRingbuf:
		return "BpfMapTypeRingbuf"
	case BpfMapTypeInodeStorage:
		return "BpfMapTypeInodeStorage"
	case BpfMapTypeTaskStorage:
		return "BpfMapTypeTaskStorage"
	}
	return fmt.Sprintf("MapType(%d)", m)
}

type ProgramType uint32

const (
	BpfProgTypeUnspec ProgramType = iota
	BpfProgTypeSocketFilter
	BpfProgTypeKprobe
	BpfProgTypeSchedCls
	BpfProgTypeSchedAct
	BpfProgTypeTracepoint
	BpfProgTypeXdp
	BpfProgTypePerfEvent
	BpfProgTypeCgroupSkb
	BpfProgTypeCgroupSock
	BpfProgTypeLwtIn
	BpfProgTypeLwtOut
	BpfProgTypeLwtXmit
	BpfProgTypeSockOps
	BpfProgTypeSkSkb
	BpfProgTypeCgroupDevice
	BpfProgTypeSkMsg
	BpfProgTypeRawTracepoint
	BpfProgTypeCgroupSockAddr
	BpfProgTypeLwtSeg6local
	BpfProgTypeLircMode2
	BpfProgTypeSkReuseport
	BpfProgTypeFlowDissector
	BpfProgTypeCgroupSysctl
	BpfProgTypeRawTracepointWritable
	BpfProgTypeCgroupSockopt
	BpfProgTypeTracing
	BpfProgTypeStructOps
	BpfProgTypeExt
	BpfProgTypeLsm
	BpfProgTypeSkLookup
)

func (p ProgramType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}

func (p ProgramType) String() string {
	switch p {
	case BpfProgTypeUnspec:
		return "BpfProgTypeUnspec"
	case BpfProgTypeSocketFilter:
		return "BpfProgTypeSocketFilter"
	case BpfProgTypeKprobe:
		return "BpfProgTypeKprobe"
	case BpfProgTypeSchedCls:
		return "BpfProgTypeSchedCls"
	case BpfProgTypeSchedAct:
		return "BpfProgTypeSchedAct"
	case BpfProgTypeTracepoint:
		return "BpfProgTypeTracepoint"
	case BpfProgTypeXdp:
		return "BpfProgTypeXdp"
	case BpfProgTypePerfEvent:
		return "BpfProgTypePerfEvent"
	case BpfProgTypeCgroupSkb:
		return "BpfProgTypeCgroupSkb"
	case BpfProgTypeCgroupSock:
		return "BpfProgTypeCgroupSock"
	case BpfProgTypeLwtIn:
		return "BpfProgTypeLwtIn"
	case BpfProgTypeLwtOut:
		return "BpfProgTypeLwtOut"
	case BpfProgTypeLwtXmit:
		return "BpfProgTypeLwtXmit"
	case BpfProgTypeSockOps:
		return "BpfProgTypeSockOps"
	case BpfProgTypeSkSkb:
		return "BpfProgTypeSkSkb"
	case BpfProgTypeCgroupDevice:
		return "BpfProgTypeCgroupDevice"
	case BpfProgTypeSkMsg:
		return "BpfProgTypeSkMsg"
	case BpfProgTypeRawTracepoint:
		return "BpfProgTypeRawTracepoint"
	case BpfProgTypeCgroupSockAddr:
		return "BpfProgTypeCgroupSockAddr"
	case BpfProgTypeLwtSeg6local:
		return "BpfProgTypeLwtSeg6local"
	case BpfProgTypeLircMode2:
		return "BpfProgTypeLircMode2"
	case BpfProgTypeSkReuseport:
		return "BpfProgTypeSkReuseport"
	case BpfProgTypeFlowDissector:
		return "BpfProgTypeFlowDissector"
	case BpfProgTypeCgroupSysctl:
		return "BpfProgTypeCgroupSysctl"
	case BpfProgTypeRawTracepointWritable:
		return "BpfProgTypeRawTracepointWritable"
	case BpfProgTypeCgroupSockopt:
		return "BpfProgTypeCgroupSockopt"
	case BpfProgTypeTracing:
		return "BpfProgTypeTracing"
	case BpfProgTypeStructOps:
		return "BpfProgTypeStructOps"
	case BpfProgTypeExt:
		return "BpfProgTypeExt"
	case BpfProgTypeLsm:
		return "BpfProgTypeLsm"
	case BpfProgTypeSkLookup:
		return "BpfProgTypeSkLookup"
	}
	return fmt.Sprintf("ProgramType(%d)", p)
}

type AttachType uint32

const (
	BpfCgroupInetIngress AttachType = iota + 1
	BpfCgroupInetEgress
	BpfCgroupInetSockCreate
	BpfCgroupSockOps
	BpfSkSkbStreamParser
	BpfSkSkbStreamVerdict
	BpfCgroupDevice
	BpfSkMsgVerdict
	BpfCgroupInet4Bind
	BpfCgroupInet6Bind
	BpfCgroupInet4Connect
	BpfCgroupInet6Connect
	BpfCgroupInet4PostBind
	BpfCgroupInet6PostBind
	BpfCgroupUdp4Sendmsg
	BpfCgroupUdp6Sendmsg
	BpfLircMode2
	BpfFlowDissector
	BpfCgroupSysctl
	BpfCgroupUdp4Recvmsg
	BpfCgroupUdp6Recvmsg
	BpfCgroupGetsockopt
	BpfCgroupSetsockopt
	BpfTraceRawTp
	BpfTraceFentry
	BpfTraceFexit
	BpfModifyReturn
	BpfLsmMac
	BpfTraceIter
	BpfCgroupInet4Getpeername
	BpfCgroupInet6Getpeername
	BpfCgroupInet4Getsockname
	BpfCgroupInet6Getsockname
	BpfXdpDevmap
	BpfCgroupInetSockRelease
	BpfXdpCpumap
	BpfSkLookup
	BpfXdp
	BpfSkSkbVerdict
)

func NewAttachType(progType ProgramType, attachType uint32) AttachType {
	if attachType > 0 {
		return AttachType(attachType)
	}

	switch progType {
	case BpfProgTypeCgroupDevice, BpfProgTypeCgroupSock, BpfProgTypeCgroupSockopt, BpfProgTypeCgroupSkb, BpfProgTypeCgroupSysctl, BpfProgTypeCgroupSockAddr:
		return BpfCgroupInetIngress
	}
	return 0
}

func (a AttachType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.String() + `"`), nil
}

func (a AttachType) String() string {
	switch a {
	case BpfCgroupInetIngress:
		return "BpfCgroupInetIngress"
	case BpfCgroupInetEgress:
		return "BpfCgroupInetEgress"
	case BpfCgroupInetSockCreate:
		return "BpfCgroupInetSockCreate"
	case BpfCgroupSockOps:
		return "BpfCgroupSockOps"
	case BpfSkSkbStreamParser:
		return "BpfSkSkbStreamParser"
	case BpfSkSkbStreamVerdict:
		return "BpfSkSkbStreamVerdict"
	case BpfCgroupDevice:
		return "BpfCgroupDevice"
	case BpfSkMsgVerdict:
		return "BpfSkMsgVerdict"
	case BpfCgroupInet4Bind:
		return "BpfCgroupInet4Bind"
	case BpfCgroupInet6Bind:
		return "BpfCgroupInet6Bind"
	case BpfCgroupInet4Connect:
		return "BpfCgroupInet4Connect"
	case BpfCgroupInet6Connect:
		return "BpfCgroupInet6Connect"
	case BpfCgroupInet4PostBind:
		return "BpfCgroupInet4PostBind"
	case BpfCgroupInet6PostBind:
		return "BpfCgroupInet6PostBind"
	case BpfCgroupUdp4Sendmsg:
		return "BpfCgroupUdp4Sendmsg"
	case BpfCgroupUdp6Sendmsg:
		return "BpfCgroupUdp6Sendmsg"
	case BpfLircMode2:
		return "BpfLircMode2"
	case BpfFlowDissector:
		return "BpfFlowDissector"
	case BpfCgroupSysctl:
		return "BpfCgroupSysctl"
	case BpfCgroupUdp4Recvmsg:
		return "BpfCgroupUdp4Recvmsg"
	case BpfCgroupUdp6Recvmsg:
		return "BpfCgroupUdp6Recvmsg"
	case BpfCgroupGetsockopt:
		return "BpfCgroupGetsockopt"
	case BpfCgroupSetsockopt:
		return "BpfCgroupSetsockopt"
	case BpfTraceRawTp:
		return "BpfTraceRawTp"
	case BpfTraceFentry:
		return "BpfTraceFentry"
	case BpfTraceFexit:
		return "BpfTraceFexit"
	case BpfModifyReturn:
		return "BpfModifyReturn"
	case BpfLsmMac:
		return "BpfLsmMac"
	case BpfTraceIter:
		return "BpfTraceIter"
	case BpfCgroupInet4Getpeername:
		return "BpfCgroupInet4Getpeername"
	case BpfCgroupInet6Getpeername:
		return "BpfCgroupInet6Getpeername"
	case BpfCgroupInet4Getsockname:
		return "BpfCgroupInet4Getsockname"
	case BpfCgroupInet6Getsockname:
		return "BpfCgroupInet6Getsockname"
	case BpfXdpDevmap:
		return "BpfXdpDevmap"
	case BpfCgroupInetSockRelease:
		return "BpfCgroupInetSockRelease"
	case BpfXdpCpumap:
		return "BpfXdpCpumap"
	case BpfSkLookup:
		return "BpfSkLookup"
	case BpfXdp:
		return "BpfXdp"
	case BpfSkSkbVerdict:
		return "BpfSkSkbVerdict"
	}
	return fmt.Sprintf("AttachType(%d)", a)
}
