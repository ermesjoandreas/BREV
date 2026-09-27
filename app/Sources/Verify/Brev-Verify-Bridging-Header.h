//
//  Brev-Verify-Bridging-Header.h
//  Brev (Verify configuration only)
//
//  The app's bridging header (Brev-Bridging-Header.h: the UniFFI C
//  declarations) plus the heap scanner that Verify/SelfScan.swift calls
//  (app/Tests/scan.h, docs/PHASE2_DESIGN.md §4.1). project.yml uses this
//  header only in the Verify configuration, whose HEADER_SEARCH_PATHS also
//  name app/Tests; Debug and Release never see scan.h.
//

#import "BrevCoreFFI.h"
#import "scan.h"
