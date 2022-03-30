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

func isNamelessMacroDefinition(line: String) -> Bool {
    let words = line.components(separatedBy: .whitespaces).filter {!$0.isEmpty}

    guard let firstWord = words.first else {
        return false
    }

    guard firstWord == ".macro" else {
        return false
    }

    if (words.count > 2) {
        // Check if there's a comment, otherwise it's a named macro
        let extraWord = words[2]
        if extraWord.hasPrefix("//") || extraWord.hasPrefix("/*") || extraWord.hasPrefix("#") {
            return true
        } else {
            return false
        }
    }
    return true
}

func isEndOfMacro(line: String) -> Bool {
    let words = line.components(separatedBy: CharacterSet(charactersIn: " \t,")).filter {!$0.isEmpty}
    if let firstWord = words.first, firstWord.hasPrefix(".endm") {
        return true
    }
    return false
}

func countMacroArguments(lines: [String]) -> Int {
    var maxArg: Int? = nil

    for line in lines {
        // Exit if at end of macro
        if isEndOfMacro(line: line) {
            break
        }

        // Ignore values in comments
        let newLine = line.components(separatedBy: "//")[0]
        // Search for argument references in each line of the macro. Note the highest argument number found.
        let argRegex = try! NSRegularExpression(pattern: "[^\\$]\\$[0-9]")
        let argRefs = argRegex.matches(in: newLine, range: NSRange(newLine.startIndex..., in: newLine)).map {
            Int(String(newLine[Range($0.range, in: newLine)!]).dropFirst(2))!
        }

        if let max = argRefs.max() {
            if maxArg == nil || max > maxArg! {
                maxArg = max
            }
        }
    }
    return maxArg != nil ? maxArg! + 1 : 0
}

func emitNamedMacro(line: String, args: Int) {
    // Assume first word is ".macro" and second word is macro's name
    let words = line.components(separatedBy: CharacterSet(charactersIn: " \t,")).filter {!$0.isEmpty}
    let macroName = words[1]

    // Substitute '<macroname>' with '<macroname> <args...>', keeping the rest of formatting same
    var newMacroName = macroName
    for i in (0..<args) {
        if i != args-1 {
            newMacroName += " arg\(i),"
        } else {
            newMacroName += " arg\(i)"
        }
    }
    print(line.replacingOccurrences(of: macroName, with: newMacroName ))
}


let fileName = CommandLine.arguments[1]
let file = try String(contentsOf: URL(fileURLWithPath: fileName), encoding: .utf8)
var lines = file.components(separatedBy: .newlines)

while !lines.isEmpty {
    var curArgs: Int

    // Process lines until the start of a macro
    curArgs = 0
    while !lines.isEmpty {
        let line = lines.removeFirst()
        if isNamelessMacroDefinition(line: line) {
            // If it's a macro changes its declaration and go to next stage
            let args = countMacroArguments(lines: lines)
            emitNamedMacro(line: line, args: args)
            curArgs = args
            break
        } else {
            // If it's outside a macro leave the text unchanged
            // Ugly but effective: avoid adding a empty line at the end.
            let isLast = lines.count == 0
            if (!isLast) {
                print(line)
            }
        }
    }

    // Process macro lines.
    while !lines.isEmpty {
        let line = lines.removeFirst()
        if isEndOfMacro(line: line) {
            print(line)
            break
        }

        // Substitute $[0-macroArgs] with \arg[0-macroArgs]
        let argRegex = try! NSRegularExpression(pattern: "([^\\$])\\$([0-9])")
        var newLine = argRegex.stringByReplacingMatches(in: line, range: NSRange(line.startIndex..., in: line), withTemplate: "$1\\\\arg$2")

        // Fix immediates
        // Sigh. clang's immediates for macro with zero argument is different.
        if curArgs == 0 {
            // Substitute hexadecimal immediates with _IMM()
            let hexRegex = try! NSRegularExpression(pattern: "\\$\\$(0[xX][0-9a-fA-F]+)")
            newLine = hexRegex.stringByReplacingMatches(in: newLine, range: NSRange(line.startIndex..., in: line), withTemplate: "_IMM($1)")
            // Substitute other immediates with _IMM()
            let immRegex = try! NSRegularExpression(pattern: "\\$\\$([0-9]+)")
            newLine = immRegex.stringByReplacingMatches(in: newLine, range: NSRange(line.startIndex..., in: line), withTemplate: "_IMM($1)")
        } else {
            // Substitute $$ with $
            let immRegex = try! NSRegularExpression(pattern: "\\$\\$")
            newLine = immRegex.stringByReplacingMatches(in: newLine, range: NSRange(line.startIndex..., in: line), withTemplate: "\\$")
        }
        print(newLine)
    }
}
