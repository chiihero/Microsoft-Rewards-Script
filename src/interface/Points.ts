export interface BrowserEarnablePoints {
    desktopSearchPoints: number | null
    mobileSearchPoints: number | null
    dailySetPoints: number
    morePromotionsPoints: number
    totalEarnablePoints: number | null
}

export interface AppEarnablePoints {
    readToEarn: number
    checkIn: number | null
    totalEarnablePoints: number | null
}

export interface MissingSearchPoints {
    mobilePoints: number
    desktopPoints: number
    edgePoints: number
    totalPoints: number
}
