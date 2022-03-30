#!/usr/bin/xcrun swift

/* Copyright (c) (2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

import Foundation
import os

struct PBXProject {
    let rootPList: NSDictionary
    let rootObject: NSDictionary
    let objects: NSDictionary
    let targets: [PBXTarget]
    var fileMap: [String : String]

    init(filePath: String) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: filePath))
        let rootPList = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as! NSDictionary
        let objects = rootPList["objects"] as! NSDictionary
        let rootObjectRef = rootPList["rootObject"] as! String
        let rootObject = objects[rootObjectRef] as! NSDictionary
        let targetRefs = rootObject["targets"] as! [String]
        let targets = targetRefs.map { PBXTarget(raw: objects[$0] as! NSDictionary, objects: objects) }

        self.rootPList = rootPList
        self.rootObject = rootObject
        self.objects = objects
        self.targets = targets
        self.fileMap = [:]

        /* Traverse the mainGroup tree to find a FileRef's actual path. */
        let mainGroup = rootObject["mainGroup"] as! String
        let object = self.objects[mainGroup] as! NSDictionary
        let children = object["children"] as! [String]
        children.forEach {
            computeFileMap(ref: $0, basePath: "")
        }
    }

    mutating func computeFileMap(ref: String, basePath: String) {
        let object = self.objects[ref] as! NSDictionary
        let type = object["isa"] as! String
        let path = object["path"] as! String?
        let sourceTree = object["sourceTree"] as! String?
        let separator = basePath != "" ? "/" : ""

        if type == "PBXGroup" {
            var newPath : String

            let children = object["children"] as! [String]
            newPath = basePath
            if path != nil {
                if sourceTree == "SOURCE_ROOT" {
                    newPath = path!
                } else {
                    newPath = basePath + separator + path!
                }
            }
            children.forEach {
                computeFileMap(ref: $0, basePath: newPath)
            }
        } else if type == "PBXFileReference" {
            var filePath : String
            let separator = basePath != "" ? "/" : ""

            if path != nil {
                if sourceTree == "SOURCE_ROOT" {
                    filePath = path!
                } else {
                    filePath = basePath + separator + path!
                }
                self.fileMap[ref] = filePath
            }
        }
    }

    func getTarget(name: String) -> PBXTarget? {
        return self.targets.first { $0.name == name }
    }

    func getTargetPublicHeaders(name: String) -> [String] {
        guard let target = self.getTarget(name: name) else {
            return []
        }
        return target.publicHeadersRefs.map { self.fileMap[$0]! }
    }

    func getTargetPrivateHeaders(name: String) -> [String] {
        guard let target = self.getTarget(name: name) else {
            return []
        }
        return target.privateHeadersRefs.map { self.fileMap[$0]! }
    }

    func getTargetProjectHeaders(name: String) -> [String] {
        guard let target = self.getTarget(name: name) else {
            return []
        }
        return target.projectHeadersRefs.map { self.fileMap[$0]! }
    }

    func getTargetSources(name: String) -> [String] {
        guard let target = self.getTarget(name: name) else {
            return []
        }
        return target.sourceRefs.map { self.fileMap[$0]! }
    }

    struct PBXTarget {
        let name: String
        let publicHeadersRefs: [String]
        let privateHeadersRefs: [String]
        let projectHeadersRefs: [String]
        let sourceRefs: [String]

        init(raw: NSDictionary, objects: NSDictionary) {
            self.name = raw["name"] as! String

            /* Get build phase useful information */
            let rawBuildPhases = raw["buildPhases"] as! NSArray
            let buildPhases = rawBuildPhases.map { PBXBuildPhase(raw: objects[$0] as! NSDictionary, objects: objects) }

            let headersBuildPhases = buildPhases.filter { $0.type == "PBXHeadersBuildPhase" }
            /* Public Headers Refs */
            var publicHeadersRefs: [String] = []
            headersBuildPhases.forEach { buildPhase in
                let publicHeadersBuildFiles = buildPhase.buildFiles.filter { $0.attributes.contains("Public") }
                publicHeadersRefs +=  publicHeadersBuildFiles.map { $0.fileRef }
            }
            self.publicHeadersRefs = publicHeadersRefs

            /* Private Headers Refs. */
            var privateHeadersRefs: [String] = []
            headersBuildPhases.forEach { buildPhase in
                let publicHeadersBuildFiles = buildPhase.buildFiles.filter { $0.attributes.contains("Private") }
                privateHeadersRefs +=  publicHeadersBuildFiles.map { $0.fileRef }
            }
            self.privateHeadersRefs = privateHeadersRefs

            /* Project Headers Refs. */
            var projectHeadersRefs: [String] = []
            headersBuildPhases.forEach { buildPhase in
                let publicHeadersBuildFiles = buildPhase.buildFiles.filter { !$0.attributes.contains("Public") && !$0.attributes.contains("Private") }
                projectHeadersRefs +=  publicHeadersBuildFiles.map { $0.fileRef }
            }
            self.projectHeadersRefs = projectHeadersRefs

            /* Source Refs */
            let sourcesBuildPhases = buildPhases.filter { $0.type == "PBXSourcesBuildPhase" }
            var sourceRefs: [String] = []
            sourcesBuildPhases.forEach { buildPhase in
                sourceRefs += buildPhase.buildFiles.map { $0.fileRef }
            }
            self.sourceRefs = sourceRefs
        }
    }

    struct PBXBuildFile {
        let fileRef: String
        let attributes: [String]

        init?(raw: NSDictionary) {
            guard let fileRef = raw["fileRef"] as? String else {
                return nil
            }
            self.fileRef = fileRef
            if let settings = raw["settings"] as? NSDictionary, let attributes = settings["ATTRIBUTES"] as? [String] {
                self.attributes = attributes
            } else {
                self.attributes = []
            }
        }
    }

    struct PBXBuildPhase {
        let type: String
        let buildFiles: [PBXBuildFile]

        init(raw: NSDictionary, objects: NSDictionary) {
            self.type = raw["isa"] as! String

            let rawFileRefs = raw["files"] as! [String]
            self.buildFiles = rawFileRefs.compactMap { (fileRef: String) -> PBXBuildFile? in
                return PBXBuildFile(raw: objects[fileRef] as! NSDictionary)
            }
        }
    }
}

func CreateCMakeList(name: String, list: [String]) -> String {
    let cmakeList = ["set (\(name)"] + list
    return cmakeList.joined(separator: "\n    ") + "\n)\n\n"
}

if CommandLine.arguments.count < 2 {
    print("\(CommandLine.arguments[0]) corecrypto.xcodeproj/project.pbxproj CoreCryptoSources.cmake")
    os.exit(1)
}

let pbxFilePath = CommandLine.arguments[1]
let cmakeFilePath = CommandLine.arguments[2]

let pbxProj = try PBXProject(filePath: pbxFilePath)
let publicHeaders = pbxProj.getTargetPublicHeaders(name: "corecrypto_headers")
let privateHeaders = pbxProj.getTargetPrivateHeaders(name: "corecrypto_headers")
let projectHeaders = pbxProj.getTargetProjectHeaders(name: "corecrypto_headers")
let ccSources = pbxProj.getTargetSources(name: "corecrypto_static")
let ccTestHeaders = pbxProj.getTargetProjectHeaders(name: "corecrypto_test")
let ccTestSources = pbxProj.getTargetSources(name: "corecrypto_test")
let ccPerfSources = pbxProj.getTargetSources(name: "corecrypto_perf")


var cmakeOutput = "# Generated by cmake_update.swift -- DO NOT EDIT\n\n"
cmakeOutput += CreateCMakeList(name: "CORECRYPTO_PUBLIC_HDRS", list: publicHeaders)
cmakeOutput += CreateCMakeList(name: "CORECRYPTO_PRIVATE_HDRS", list: privateHeaders)
cmakeOutput += CreateCMakeList(name: "CORECRYPTO_PROJECT_HDRS", list: projectHeaders)
cmakeOutput += CreateCMakeList(name: "CORECRYPTO_SRCS", list: ccSources)
cmakeOutput += CreateCMakeList(name: "CORECRYPTO_TEST_HDRS", list: ccTestHeaders)
cmakeOutput += CreateCMakeList(name: "CORECRYPTO_TEST_SRCS", list: ccTestSources)
cmakeOutput += CreateCMakeList(name: "CORECRYPTO_PERF_SRCS", list: ccPerfSources)
try! cmakeOutput.write(to: URL(fileURLWithPath: cmakeFilePath), atomically: false, encoding: .utf8)

