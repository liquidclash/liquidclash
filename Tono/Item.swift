//
//  Item.swift
//  LiquidClash
//
//  Created by LiquidClash on 2026/3/29.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
